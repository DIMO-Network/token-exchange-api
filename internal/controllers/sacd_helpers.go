package controllers

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
)

func userGrantMap(record *models.PermissionRecord, nftAddr string, tokenID int64) (map[string]bool, map[string]map[string]*shared.StringSet, error) {
	userPermGrants := make(map[string]bool)
	cloudEvtGrants := make(map[string]map[string]*shared.StringSet)

	// Aggregates all the permission and attestation grants the user has.
	for _, agreement := range record.Data.Agreements {
		now := time.Now()
		if agreement.EffectiveAt != nil && agreement.EffectiveAt.After(now) {
			continue
		}

		if agreement.ExpiresAt != nil && agreement.ExpiresAt.Before(now) {
			continue
		}

		switch agreement.Type {
		case "cloudevent":
			if err := validAssetDID(agreement.Asset, nftAddr, tokenID); err != nil {
				return nil, nil, fmt.Errorf("failed to validate attestation asset: %s", agreement.Asset)
			}

			if agreement.EffectiveAt != nil && !agreement.EffectiveAt.IsZero() && now.Before(*agreement.EffectiveAt) {
				continue // agreement not yet in effective
			}

			if agreement.ExpiresAt != nil && !agreement.ExpiresAt.IsZero() && agreement.ExpiresAt.Before(now) {
				return nil, nil, errors.New("agreement expired")
			}

			if _, ok := cloudEvtGrants[agreement.EventType]; !ok {
				cloudEvtGrants[agreement.EventType] = map[string]*shared.StringSet{}
			}

			source := strings.ToLower(agreement.Source)
			if _, ok := cloudEvtGrants[agreement.EventType][source]; !ok {
				cloudEvtGrants[agreement.EventType][source] = shared.NewStringSet()
			}

			for _, id := range agreement.IDs {
				cloudEvtGrants[agreement.EventType][source].Add(id)
			}

		case "permission":
			if err := validAssetDID(record.Data.Asset, nftAddr, tokenID); err != nil {
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

// validAssetDID verifies that the provided DID matches the NFT contract address
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
func validAssetDID(did string, nftContractAddr string, tokenID int64) error {
	decodedDID, err := cloudevent.DecodeERC721DID(did)
	if err != nil {
		return fmt.Errorf("failed to decode DID: %w", err)
	}

	if decodedDID.ContractAddress != common.HexToAddress(nftContractAddr) {
		return fmt.Errorf("DID contract address %s does not match request contract address %s",
			decodedDID.ContractAddress.Hex(), nftContractAddr)
	}

	if int64(decodedDID.TokenID.Int64()) != tokenID {
		return fmt.Errorf("DID token ID %d does not match request token ID %d",
			decodedDID.TokenID, tokenID)
	}

	return nil
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
