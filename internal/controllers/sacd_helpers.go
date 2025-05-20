package controllers

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
)

func userGrantMap(record *models.PermissionRecord, nftAddr string, tokenID int64) (map[string]bool, map[string]map[string]*shared.StringSet, error) {
	userPermGrants := make(map[string]bool)
	cloudEvtGrants := make(map[string]map[string]*shared.StringSet)

	// Aggregates all the permission and attestation grants the user has.
	for _, agreement := range record.Data.Agreements {
		if agreement.EffectiveAt != nil {
			if agreement.EffectiveAt.After(time.Now()) {
				continue
			}
		}

		if agreement.ExpiresAt != nil {
			if agreement.ExpiresAt.Before(time.Now()) {
				continue
			}
		}

		switch agreement.Type {
		case "cloudevent":
			if valid, err := validateAssetDID(agreement.Asset, nftAddr, tokenID); err != nil || !valid {
				return nil, nil, fmt.Errorf("failed to validate attestation asset: %s", agreement.Asset)
			}

			if agreement.EffectiveAt != nil && !agreement.EffectiveAt.IsZero() {
				if time.Now().Before(*agreement.EffectiveAt) {
					return nil, nil, errors.New("agreement not yet in effect")
				}
			}

			if agreement.ExpiresAt != nil && !agreement.ExpiresAt.IsZero() {
				if agreement.ExpiresAt.Before(time.Now()) {
					return nil, nil, errors.New("agreement expired")
				}
			}

			if _, ok := cloudEvtGrants[agreement.EventType]; !ok {
				cloudEvtGrants[agreement.EventType] = map[string]*shared.StringSet{}
			}

			source := tokenclaims.GlobalAttestationPermission
			if agreement.Source != nil {
				source = *agreement.Source
			}

			if _, ok := cloudEvtGrants[agreement.EventType][source]; !ok {
				cloudEvtGrants[agreement.EventType][source] = shared.NewStringSet()
			}

			for _, id := range agreement.IDs {
				cloudEvtGrants[agreement.EventType][source].Add(id)
			}

		case "permissions":
			if valid, err := validateAssetDID(record.Data.Asset, nftAddr, tokenID); err != nil || !valid {
				return nil, nil, fmt.Errorf("failed to validate permission asset: %s", record.Data.Asset)
			}

			// Add permissions from this agreement
			for _, permission := range agreement.Permissions {
				userPermGrants[permission.Name] = true
			}
		}
	}

	return userPermGrants, cloudEvtGrants, nil
}

// validateAssetDID verifies that the provided DID matches the NFT contract address
// and token ID specified in the permission token request.
//
// Parameters:
//   - did: The decentralized identifier string to validate, typically in the format "did:nft:..."
//   - nftContractAddr: NFT contract address from token request and token ID to match against
//   - tokenID: Token ID from token request
//
// Returns:
//   - bool: true if the DID is valid and matches the request parameters, false otherwise
//   - error: An error describing why validation failed, or nil if validation succeeded
func validateAssetDID(did string, nftContractAddr string, tokenID int64) (bool, error) {
	decodedDID, err := cloudevent.DecodeERC721DID(did)
	if err != nil {
		return false, fmt.Errorf("failed to decode DID: %w", err)
	}

	if decodedDID.ContractAddress != common.HexToAddress(nftContractAddr) {
		return false, fmt.Errorf("DID contract address %s does not match request contract address %s",
			decodedDID.ContractAddress.Hex(), nftContractAddr)
	}

	if int64(decodedDID.TokenID.Int64()) != tokenID {
		return false, fmt.Errorf("DID token ID %d does not match request token ID %d",
			decodedDID.TokenID, tokenID)
	}

	// If we get here, the DID is valid for the given request
	return true, nil
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
