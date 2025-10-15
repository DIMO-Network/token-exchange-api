# Token Exchange API - Developer Guide

## Table of Contents

1. [Overview](#overview)
2. [Request Flow Diagram](#request-flow-diagram)
3. [System Components](#system-components)
4. [The Migration Story: From Privileges to Permissions](#the-migration-story-from-privileges-to-permissions)
5. [Access Control Deep Dive](#access-control-deep-dive)
6. [Known Behaviors & Gotchas](#known-behaviors--gotchas)
7. [Development Guide](#development-guide)

## Overview

The Token Exchange API validates and exchanges permissions for DIMO assets (vehicles). Users send requests specifying what permissions they need, and the service validates those requests against on-chain data and SACD (Smart Agreement for Controlled Data) documents, then returns signed JWT tokens containing the validated permissions.

The service provides two interfaces:

- **HTTP REST API**: Used by most clients to exchange developer tokens for privilege tokens
- **gRPC API**: Used by internal services (like Webhooks) to check access permissions without needing full token exchange

Both interfaces share identical validation logic through a centralized access control service.

## Request Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENT REQUEST                                   │
│  HTTP: POST /v1/tokens/exchange                                         │
│  gRPC: AccessCheck()                                                    │
│                                                                          │
│  Old Format:                        New Format:                         │
│  {                                  {                                   │
│    "nftContractAddress": "0x...",    "asset": "did:erc721:137:0x...:7",│
│    "tokenId": 7,                     "permissions": [                   │
│    "privileges": [1, 2, 3]             "privilege:GetLocation"          │
│  }                                   ]                                  │
│                                    }                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                          CONTROLLER LAYER                                │
│                                                                          │
│  1. Parse Request (HTTP/gRPC)                                           │
│  2. Extract User's Ethereum Address                                     │
│  3. Convert to Standard Format                                          │
│                                                                          │
│     ┌───────────────────────────────────────┐                          │
│     │     AccessRequest                      │                          │
│     │  ─────────────────────────────────    │                          │
│     │  asset:        ERC721DID              │                          │
│     │  permissions:  []string               │                          │
│     │  eventFilters: []EventFilter          │                          │
│     └───────────────────────────────────────┘                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                       ACCESS VALIDATION SERVICE                          │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │  PRIMARY PATH: SACD Document Validation                        │   │
│  │                                                                  │   │
│  │  1. Query On-Chain Permission Record                           │   │
│  │     └─► Get IPFS URL + Template ID                             │   │
│  │                                                                  │   │
│  │  2. Fetch SACD Document from IPFS                              │   │
│  │     └─► Structured permission grants + cloud event agreements  │   │
│  │                                                                  │   │
│  │  3. Validate Document                                           │   │
│  │     └─► Check grantor signature                                │   │
│  │     └─► Verify time bounds (effectiveAt, expiresAt)            │   │
│  │     └─► Extract permission grants                              │   │
│  │                                                                  │   │
│  │  4. Template Validation (if applicable)                         │   │
│  │     └─► Verify template permissions match SACD grants          │   │
│  │                                                                  │   │
│  │  5. Evaluate Access                                             │   │
│  │     └─► Do grants cover requested permissions?                 │   │
│  │     └─► Do cloud event agreements match filters?               │   │
│  │                                                                  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                               ↓ FAIL                                     │
│                               ↓ (No cloud events)                        │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │  FALLBACK PATH: Legacy Bit-Based Validation                    │   │
│  │                                                                  │   │
│  │  1. Convert permission names → privilege IDs                    │   │
│  │     └─► "privilege:GetLocation" → ID 3                         │   │
│  │                                                                  │   │
│  │  2. Convert IDs → bit array mask                                │   │
│  │     └─► Each privilege uses 2 bits                             │   │
│  │                                                                  │   │
│  │  3. Query On-Chain Contract                                     │   │
│  │     └─► Call GetPermissions(address, tokenId, grantee)         │   │
│  │                                                                  │   │
│  │  4. Evaluate Permission Bits                                    │   │
│  │     └─► Bitwise AND: granted & requested                       │   │
│  │                                                                  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
                              ┌──────────┐
                              │ APPROVED │
                              └──────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                      TOKEN SIGNING (HTTP only)                           │
│                                                                          │
│  1. Build JWT Claims                                                    │
│     └─► Include both new format (asset, permissions)                   │
│     └─► Include old format (contract address, tokenId, privilege IDs)  │
│     └─► Add cloud event filters if present                             │
│                                                                          │
│  2. Sign Token with DEX Service                                         │
│                                                                          │
│  3. Return Signed JWT                                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                              RESPONSE                                    │
│                                                                          │
│  HTTP: { "token": "eyJhbGc..." }                                        │
│  gRPC: { "hasAccess": true, "reason": "" }                              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## System Components

This section walks through each component in the request flow, explaining what it does and why.

### Controller Layer

**What it does**: The controller is the entry point for all requests. It handles the messy work of dealing with different input formats and transport protocols (HTTP vs gRPC).

**Key responsibilities**:

- Parse incoming requests from HTTP or gRPC
- Extract the user's Ethereum address from request context
- Convert everything into a single standardized format: `AccessRequest`
- Handle backward compatibility between old and new request formats

**Why it matters**: By normalizing all inputs into `AccessRequest`, the controller ensures that everything downstream (validation, signing) works with a single, consistent data structure. This means:

- HTTP and gRPC can share identical validation logic
- Adding new transport protocols is trivial
- Testing becomes easier (no need to mock HTTP/gRPC machinery)

### The AccessRequest: Universal Format

```go
type AccessRequest struct {
    Asset        ERC721DID      // The asset being accessed (DID format)
    Permissions  []string       // Requested permission names
    EventFilters []EventFilter  // Requested cloud events (optional)
}
```

**What it is**: The single data structure that all validation logic operates on. Every request, regardless of source or format, gets converted into this structure.

**Why it exists**: This design implements separation of concerns:

- Controllers worry about I/O (parsing, formatting, transport)
- Access service worries about authorization (validation, on-chain checks)
- Neither needs to know about the other's details

### Access Validation Service

**What it does**: This is the heart of the system. It determines whether a user has the permissions they're requesting. It tries two validation strategies in order.

#### Primary Path: SACD Document Validation

**What it is**: The modern, flexible validation approach using cryptographically signed documents stored on IPFS.

**How it works**:

1. **Query on-chain**: Fetch the current permission record for the asset, which contains an IPFS URL and optional template ID
2. **Fetch SACD**: Retrieve the document from IPFS containing structured permission grants
3. **Validate document**: Verify the grantor's cryptographic signature and time bounds
4. **Extract grants**: Pull out permission names and cloud event agreements from the document
5. **Template check**: If a template ID exists, verify the template permissions match the SACD grants
6. **Evaluate**: Check if the grants cover all requested permissions and cloud event filters

**What it supports**:

- Named permissions (e.g., "privilege:GetNonLocationHistory")
- Cloud event filters (multi-dimensional access control)
- Time-based permissions (effectiveAt, expiresAt timestamps)
- Template-based permissions
- Cryptographic proof of authorization

**When it's used**: Always attempted first. Required if cloud event filters are requested.

#### Fallback Path: Legacy Bit-Based Validation

**What it is**: The original, simpler validation method using on-chain permission bits.

**How it works**:

1. **Convert to IDs**: Translate permission names back to numeric privilege IDs using a mapping table
2. **Build bit mask**: Each privilege uses 2 bits, so ID 3 maps to bits 6-7
3. **Query contract**: Call the on-chain `GetPermissions()` function to get the user's granted permission bits
4. **Bitwise evaluation**: Perform bitwise AND to check if granted bits include requested bits

**What it supports**:

- Simple permission checks only
- No cloud events
- No time restrictions
- No templates

**When it's used**:

- When SACD validation fails (document not found, invalid, or inaccessible)
- AND no cloud event filters are requested
- Only works for basic permission checks

**Important limitation**: Cloud event filters CANNOT be validated through the legacy path. If events are requested and SACD validation fails, the entire request is denied.

### Token Signing (HTTP Only)

**What it does**: Creates and signs a JWT token containing the validated permissions.

**How it works**:

1. **Build claims**: Package the validated permissions into JWT claims
2. **Dual format**: Include both new format (asset DID, permission names) and old format (contract address, token ID, privilege IDs) for backward compatibility
3. **Sign**: Use the DEX service to cryptographically sign the token
4. **Return**: Send the signed JWT back to the client

**Why gRPC skips this**: The gRPC interface is used by internal services (like Webhooks) that only need to know if access is allowed or denied. They don't need a signed token for third parties.

## The Migration Story: From Privileges to Permissions

### What Changed?

This repo underwent a significant API evolution. Understanding this migration is critical for debugging.

**Old Format** (Deprecated but still supported):

```json
{
  "nftContractAddress": "0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF",
  "tokenId": 7,
  "privileges": [1, 2, 3]
}
```

**New Format** (Current):

```json
{
  "asset": "did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:7",
  "permissions": [
    "privilege:GetNonLocationHistory",
    "privilege:ExecuteCommands"
  ]
}
```

### Why the Change?

1. **Support for multiple asset types**: DIDs support both `did:erc721` and `did:ethr`
2. **Compatibility with SACD**: SACD documents use permission names, not numeric IDs
3. **Better semantic clarity**: Developers historically struggled with the bit-based system

### How Backward Compatibility Works

The magic happens in the controller during the conversion to `AccessRequest`:

**Asset Extraction**:

- If `asset` field is provided → decode the DID
- Otherwise → build DID from `nftContractAddress` + `tokenId`

**Permission Extraction**:

- If `permissions` are provided → use them directly
- Otherwise → convert `privileges` using the mapping table:

```go
PrivilegeIDToName[1] = "privilege:GetNonLocationHistory"
PrivilegeIDToName[2] = "privilege:ExecuteCommands"
PrivilegeIDToName[3] = "privilege:GetCurrentLocation"
PrivilegeIDToName[4] = "privilege:GetLocationHistory"
// ... etc
```

**During Validation**:

- SACD validation works directly with permission names
- Legacy validation converts names BACK to IDs using the reverse map
- JWT tokens include BOTH formats for downstream compatibility

This bidirectional conversion means old clients keep working while new clients get better semantics.

## Access Control Deep Dive

### Permission vs. Cloud Event Validation

The system validates two fundamentally different types of access requests:

#### Permissions

Permissions are straightforward boolean checks:

- **Question**: "Does user have `privilege:ExecuteCommands`?"
- **Evaluation**: String matching against granted permission names
- **Single dimension**: Either you have it or you don't

Example: User requests `["privilege:GetLocation", "privilege:GetHistory"]`. The system checks if both strings exist in the user's granted permissions.

#### Cloud Events

Cloud events are multi-dimensional access control:

- **Four dimensions**: eventType, source, IDs, tags
- **Wildcard support**: Each dimension can use `"*"` as a global identifier meaning "all"
- **Complex matching**: Must match on ALL dimensions simultaneously

### SACD Documents

SACD documents are cryptographically signed permission grants stored on IPFS. They provide the modern, flexible approach to access control.

#### Structure

```json
{
  "grantor": {"address": "0x..."},
  "grantee": {"address": "0x..."},
  "effectiveAt": "2024-01-01T00:00:00Z",
  "expiresAt": "2025-01-01T00:00:00Z",
  "permissionTemplateId": "1",
  "agreements": [
    {
      "type": "permission",
      "asset": "did:erc721:137:0x...:7",
      "permissions": [{"name": "privilege:GetNonLocationHistory"}]
    },
    {
      "type": "cloudevent",
      "asset": "did:erc721:137:0x...:7",
      "eventType": "dimo.attestation",
      "source": "0xSourceAddress",
      "ids": ["*"],
      "tags": ["*"]
    }
  ]
}
```

#### Key Fields

- **grantor**: The owner of the asset who is granting permissions
- **grantee**: The user receiving the permissions
- **effectiveAt/expiresAt**: Time bounds for when permissions are valid
- **permissionTemplateId**: Optional reference to a permission template
- **agreements**: Array of permission and cloud event grants

#### Validation Flow

When validating against a SACD document:

1. **Fetch record**: Query the on-chain contract for the permission record, which contains the IPFS URL
2. **Retrieve document**: Fetch the SACD JSON document from IPFS
3. **Verify signature**: Validate the grantor's cryptographic signature on the document
4. **Check time bounds**: Ensure current time is between effectiveAt and expiresAt
5. **Extract grants**: Parse all permission and cloud event agreements
6. **Template validation**: If a template ID exists, verify the template is active and permissions match
7. **Evaluate access**: Check if the grants cover all requested permissions and event filters

### Template-Based Permissions

Templates provide a way to define reusable permission sets. When a SACD references a template:

1. The system queries the template contract for the template's current state
2. Verifies the template is active (not disabled)
3. Compares template permissions against SACD grants
4. If they don't match, access is denied (prevents template bypass attacks)

This ensures that if a template is modified or disabled, existing SACD documents referencing it are automatically affected.

### Why Two Validation Paths?

**SACD validation is preferred** because it provides:

- Human-readable permission names
- Cloud event access control
- Time-bound permissions
- Cryptographic proof of authorization
- Template support

**Legacy validation exists** because:

- Older permission grants only set on-chain bits (no SACD document)
- Backward compatibility with existing integrations

The system automatically tries SACD first, then falls back to legacy if needed. This means old permission grants keep working while new ones get enhanced features.

## Known Behaviors & Gotchas

### DID Types: ERC-721 vs ethr

To learn more about DID types, see the [DIMO DID](https://github.com/DIMO-Network/cloudevent?tab=readme-ov-file#decentralized-identifier-did-formats) documentation.

### Cloud Event Wildcards

The global identifier `"*"` means "all" for that dimension. Common patterns:

```json
// Grant access to ALL events from a specific source
{
  "eventType": "*",
  "source": "0xSourceAddress",
  "ids": ["*"],
  "tags": ["*"]
}

// Grant access to specific event type from ANY source
{
  "eventType": "dimo.attestation",
  "source": "*",
  "ids": ["*"],
  "tags": ["insurance"]
}
```

### Testing

```bash
# Run all tests
make test
```

### Architecture Principles

When extending or modifying the service, keep these design principles in mind:

1. **Single Conversion Point**: All inputs (HTTP, gRPC, old format, new format) convert to `AccessRequest` in controllers only
2. **Centralized Validation**: All authorization logic lives in the access service
3. **Shared Logic**: HTTP and gRPC use identical validation paths (only I/O differs)
4. **Backward Compatibility**: Support both old and new request formats through bidirectional conversion
5. **Fallback Strategy**: Always try SACD first, fall back to legacy if safe
6. **Separation of Concerns**: Controllers handle I/O, access service handles authorization

### Key Data Structures

**TokenRequest** (HTTP/API input):

- New fields: `asset` (DID string), `permissions` (string array)
- Deprecated fields: `nftContractAddress`, `tokenId`, `privileges` (numeric array)

**AccessRequest** (internal standard format)

- `asset`: ERC721DID struct
- `permissions`: String array
- `eventFilters`: Array of EventFilter structs

**SACDData** (IPFS document):

- `grantor`, `grantee`: Ethereum addresses
- `agreements`: Array of permission and cloud event grants
- `permissionTemplateID`: Optional template reference
- `effectiveAt`, `expiresAt`: Time bounds

## Summary

The key to understanding this system:

1. **Everything flows through `AccessRequest`** - the universal internal format that enables code reuse
2. **Two validation paths exist**: SACD (modern, feature-rich) and legacy (simple, backward compatible)
3. **Controllers standardize, services validate** - clean separation of I/O and authorization logic
4. **Backward compatibility through conversion** - old API formats work seamlessly via bidirectional mapping
5. **Cloud events require SACD** - the legacy path cannot validate multi-dimensional access control

When debugging or extending the service, always trace the request flow: **Controller → AccessRequest → Access Service → Response**. The architecture is straightforward once you internalize these core concepts.
