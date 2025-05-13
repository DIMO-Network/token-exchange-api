package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
)

// getValidSacdDoc fetches and validates a SACD from IPFS.
// It retrieves the document using the provided source identifier, attempts to parse it as JSON,
// and verifies that it has the correct type for a DIMO SACD document.
//
// Parameters:
//   - ctx: The context for the IPFS request, which can be used for cancellation and timeouts
//   - source: The IPFS content identifier (CID) for the SACD document, typically with an "ipfs://" prefix
//
// Returns:
//   - *PermissionRecord: A pointer to the parsed permission record if valid, or nil if the document
//     could not be fetched, parsed, or doesn't have the correct type
func (t *TokenExchangeController) getValidSacdDoc(ctx context.Context, source string) (*models.PermissionRecord, error) {
	sacdDoc, err := t.ipfsService.Fetch(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JSON from IPFS: %w", err)
	}

	var record models.PermissionRecord
	if err := json.Unmarshal(sacdDoc, &record); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}

	if record.Type != "dimo.sacd" {
		return nil, fmt.Errorf("invalid type: expected 'dimo.sacd', got '%s'", record.Type)
	}

	return &record, nil
}

// evaluateSacdDoc validates a SACD to determine if the requesting user has all the requested privileges.
// It checks the validity period of the document, verifies the grantee address matches the requester,
// and confirms all requested privileges are granted in the document.
//
// Parameters:
//   - c: The Fiber context for the HTTP request
//   - record: The SACD permission record containing the granted permissions and validity period
//   - pr: The permission token request containing the requested privileges and token information
//   - grantee: The Ethereum address of the user requesting permissions
//
// Returns:
//   - error: An error if the document is invalid, expired, or missing requested permissions;
//     nil if all permissions are valid and the token is successfully created and returned
func (t *TokenExchangeController) evaluateSacdDoc(c *fiber.Ctx, record *models.PermissionRecord, pr *PermissionTokenRequest, grantee *common.Address) error {
	now := time.Now()
	if now.Before(record.Data.EffectiveAt) || now.After(record.Data.ExpiresAt) {
		return fiber.NewError(fiber.StatusBadRequest, "Permission record is expired or not yet effective")
	}

	if record.Data.Grantee.Address != grantee.Hex() {
		return fiber.NewError(fiber.StatusBadRequest, "Grantee address in permission record doesn't match requester")
	}

	// Aggregates all the permissions the user has.
	userPermissions := make(map[string]bool)
	for _, agreement := range record.Data.Agreements {
		// Skip non permission types
		if agreement.Type != "permissions" {
			continue
		}

		// Validate the asset DID if it exists in the record
		valid, err := t.validateAssetDID(agreement.Asset, pr)
		if err != nil || !valid {
			continue
		}

		// Add permissions from this agreement
		for _, permission := range agreement.Permissions {
			userPermissions[permission.Name] = true
		}
	}

	// Check if all requested privileges are present in the permissions
	var missingPermissions []int64

	for _, privID := range pr.Privileges {
		// Look up the permission name for this privilege ID
		permName, exists := PermissionMap[int(privID)]
		if !exists {
			// If we don't have a mapping for this privilege ID, consider it missing
			missingPermissions = append(missingPermissions, privID)
			continue
		}

		// Check if the user has this permission
		if !userPermissions[permName] {
			missingPermissions = append(missingPermissions, privID)
		}
	}

	// If any permissions are missing, return an error
	if len(missingPermissions) > 0 {
		return fiber.NewError(fiber.StatusBadRequest,
			fmt.Sprintf("Address %s lacks permissions %v on token id %d for asset %s.",
				grantee.Hex(), missingPermissions, pr.TokenID, pr.NFTContractAddress))
	}

	// If we get here, all permissions are valid
	return t.createAndReturnToken(c, pr, grantee)
}

func intArrayTo2BitArray(indices []int64, length int) (*big.Int, error) {
	mask := big.NewInt(0)

	for _, index := range indices {
		if index < 0 || index >= int64(length) {
			return big.NewInt(0), fmt.Errorf("invalid index %d. These must be non-negative and less than %d", index, length)
		}
		mask.SetBit(mask, int(index*2), 1)
		mask.SetBit(mask, int(index*2+1), 1)
	}

	return mask, nil
}

// validateAssetDID verifies that the provided DID matches the NFT contract address
// and token ID specified in the permission token request.
//
// Parameters:
//   - did: The decentralized identifier string to validate, typically in the format "did:nft:..."
//   - req: The permission token request containing the NFT contract address and token ID to match against
//
// Returns:
//   - bool: true if the DID is valid and matches the request parameters, false otherwise
//   - error: An error describing why validation failed, or nil if validation succeeded
func (t *TokenExchangeController) validateAssetDID(did string, req *PermissionTokenRequest) (bool, error) {
	decodedDID, err := cloudevent.DecodeNFTDID(did)
	if err != nil {
		return false, fmt.Errorf("failed to decode DID: %w", err)
	}

	requestNFTAddr := common.HexToAddress(req.NFTContractAddress)

	if decodedDID.ContractAddress != requestNFTAddr {
		return false, fmt.Errorf("DID contract address %s does not match request contract address %s",
			decodedDID.ContractAddress.Hex(), requestNFTAddr.Hex())
	}

	if int64(decodedDID.TokenID) != req.TokenID {
		return false, fmt.Errorf("DID token ID %d does not match request token ID %d",
			decodedDID.TokenID, req.TokenID)
	}

	// If we get here, the DID is valid for the given request
	return true, nil
}
