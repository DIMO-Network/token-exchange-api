# Token Exchange API

Exchange your DIMO Developer License JWT for access tokens with specific permissions for DIMO Asset.

## Quick Start

**Endpoint**: `POST https://token-exchange-api.dimo.zone/v1/tokens/exchange`

**Authentication**: Include your Developer License JWT in the `Authorization` header:

```
Authorization: Bearer <your-developer-license-token>
```

## Request Format

```json
{
  "asset": "did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:7",
  "permissions": [
    "privilege:GetNonLocationHistory",
    "privilege:GetLocationHistory"
  ],
  "audience": ["my-app"]
}
```

### Fields

- **asset** (required): The vehicle DID in format `did:erc721:{chainId}:{contractAddress}:{tokenId}`
- **permissions** : Array of permission names (see Available Permissions below)
- **cloudEvents** : Cloud event filters for document accesss
- **audience** : Array of intended audiences for the token

## Available Permissions

### Vehicle Data Permissions

| Permission                         | Description                                          |
| ---------------------------------- | ---------------------------------------------------- |
| `privilege:GetNonLocationHistory`  | Access to all historical non-location data           |
| `privilege:GetLocationHistory`     | Access to all historical location data               |
| `privilege:GetApproximateLocation` | Access to approximate location                       |
| `privilege:GetVINCredential`       | Access to VIN credential                             |
| `privilege:GetRawData`             | Access to raw vehicle data                           |
| `privilege:ExecuteCommands`        | Execute commands on the vehicle (lock, unlock, etc.) |

### Manufacturer Permissions

| Permission                                     | Description                        |
| ---------------------------------------------- | ---------------------------------- |
| `privilege:ManufacturerMintDevice`             | Mint new devices                   |
| `privilege:ManufacturerDistributeDevice`       | Distribute devices                 |
| `privilege:ManufacturerFactoryReset`           | Factory reset devices              |
| `privilege:ManufacturerDeviceReprovision`      | Force remint aftermarket devices   |
| `privilege:ManufacturerDeviceDefinitionInsert` | Add device definitions on-chain    |
| `privilege:ManufacturerDeviceLastSeen`         | Access device last seen timestamps |

## Cloud Events (Optional)

Request access to specific streaming data using cloud event filters:

```json
{
  "asset": "did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:7",
  "permissions": ["privilege:GetLiveData"],
  "cloudEvents": {
    "events": [
      {
        "eventType": "dimo.attestation",
        "source": "0xAddr",
        "ids": ["*"],
        "tags": ["insurance, registration"]
      }
    ]
  }
}
```

### Cloud Event Fields

- **eventType**: Type of event (e.g., `dimo.attestation`, or `*` for all)
- **source**: Event source identifier (e.g., `0xAddr`, or `*` for all)
- **ids**: Array of signal IDs (e.g., `["uuid"]`, or `["*"]` for all)
- **tags**: Array of tags (e.g., `["insurance, registration"]`, or `["*"]` for all)

Use `"*"` as a wildcard to match all values for that dimension.

## Response

Successful response returns a signed JWT token:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Use this token to authenticate requests to other DIMO services.

## Asset DIDs

### Vehicle NFTs (ERC-721)

```
did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:7
           ↑                    ↑                       ↑
        chain ID          contract address          token ID
```

### User Level Access (ethr)

```
did:ethr:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF
         ↑                    ↑
      chain ID          contract address
```

Use `did:ethr` format for user level permissions without specifying a token ID.

## Example Requests

### Basic Permission Request

```bash
curl -X POST https://token-exchange-api.dimo.zone/v1/tokens/exchange \
  -H "Authorization: Bearer <your-dev-license>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset": "did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:7",
    "permissions": [
      "privilege:GetNonLocationHistory",
      "privilege:GetLocationHistory"
    ]
  }'
```

### Request with Cloud Events

```bash
curl -X POST https://token-exchange-api.dimo.zone/v1/tokens/exchange \
  -H "Authorization: Bearer <your-dev-license>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset": "did:erc721:137:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF:7",
    "permissions": ["privilege:GetLiveData"],
    "cloudEvents": {
      "events": [
        {
          "eventType": "dimo.attestation",
          "source": "*",
          "ids": ["*"],
          "tags": ["insurance, registration"]
        }
      ]
    }
  }'
```

### Manufacturer Permission Request

```bash
curl -X POST https://token-exchange-api.dimo.zone/v1/tokens/exchange \
  -H "Authorization: Bearer <your-dev-license>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset": "did:ethr:137:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
    "permissions": [
      "privilege:ManufacturerMintDevice",
      "privilege:ManufacturerDeviceDefinitionInsert"
    ]
  }'
```

---

📖 **For service developers**: See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for architecture details, testing, and contribution guidelines.

## Signer check

Developer JWTs carry `signer_address`, the license signer (API key) that minted them. On every
exchange, token-exchange-api checks that this signer is still enabled on the license in
`ethereum_address`, whatever the token's audience. Addresses that aren't licenses are skipped.
Answers are cached for 60 s; Identity and chain calls time out after 3 s.
`SignerCheck` (gRPC) serves the same answers to vehicle-triggers-api, tesla-oracle and
credit-tracker.

| Setting                       | Values                            | Effect                                                                                                                                                               |
| ----------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SIGNER_CHECK_MODE`           | `enforce` (default), `log`, `off` | `enforce` answers 403 `signer no longer authorized for this license` or 503 `could not verify signer`; `log` only logs and counts; `off` skips the check.            |
| `SIGNER_CLAIM_REQUIRED_AFTER` | Unix time, unset by default       | License tokens issued after it without `signer_address` get the 403. If Identity can't say whether the address is a license, the token passes and counts as `error`. |

- **Metric:** `signer_check_total{service,result}`, with `result` one of `allowed`, `denied`, `error`, `skipped`.
- **Alert:** `SignerCheckErrors` fires when `error` exceeds 1% of non-skipped checks (`allowed` + `denied` + `error`) for 5 minutes.
- **Rollback order:**
  - turn the console's `NEXT_PUBLIC_TEAM_DATA_ACCESS_ENABLED` off;
  - set `SIGNER_CHECK_MODE=off` (or roll back) on vehicle-triggers-api, tesla-oracle and credit-tracker, then token-exchange-api;
  - roll back dex last.
