package controllers

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
)

func evaluateCloudEvent(agreement map[string]map[string]*set.StringSet, req EventFilter) error {

	if !common.IsHexAddress(req.Source) && req.Source != tokenclaims.GlobalIdentifier {
		return fmt.Errorf("requested source %s invalid: must be %s or valid hex address", req.Source, tokenclaims.GlobalIdentifier)
	}

	if len(req.IDs) == 0 {
		return fmt.Errorf("must request at least one cloudevent id or global access request (%s)", tokenclaims.GlobalIdentifier)
	}

	grantedAggs, ok := agreement[req.EventType]
	if !ok {
		return fmt.Errorf("lacking grant for requested event type: %s", req.EventType)
	}

	globalGrantIDs, ok := grantedAggs[tokenclaims.GlobalIdentifier]
	if ok && globalGrantIDs.Contains(tokenclaims.GlobalIdentifier) {
		return nil
	}

	sourceGrantIDs, ok := grantedAggs[req.Source]
	if globalGrantIDs == nil && !ok {
		return fmt.Errorf("no %s grants for source: %s", req.EventType, req.Source)
	}

	if missingIDs := evaluateIDsByGrantSource(globalGrantIDs, sourceGrantIDs, req.IDs); len(missingIDs) > 0 {
		return fmt.Errorf("lacking %s grant for source %s with ids: %s", req.EventType, req.Source, strings.Join(missingIDs, ","))
	}

	return nil
}

func evaluateIDsByGrantSource(globalGrants *set.StringSet, sourceGrants *set.StringSet, requestedIDs []string) []string {
	if (globalGrants != nil && globalGrants.Contains(tokenclaims.GlobalIdentifier)) || (sourceGrants != nil && sourceGrants.Contains(tokenclaims.GlobalIdentifier)) {
		return nil
	}
	var missingIDs []string
	for _, reqID := range requestedIDs {
		if (globalGrants != nil && !globalGrants.Contains(reqID)) && (sourceGrants != nil && !sourceGrants.Contains(reqID)) {
			missingIDs = append(missingIDs, reqID)
		}
	}
	return missingIDs
}

func userGrantMap(record *models.PermissionRecord, nftAddr string, tokenID int64) (map[string]bool, map[string]map[string]*set.StringSet, error) {
	userPermGrants := make(map[string]bool)
	cloudEvtGrants := make(map[string]map[string]*set.StringSet)

	if err := validAssetDID(record.Data.Asset, nftAddr, tokenID); err != nil {
		return nil, nil, fmt.Errorf("failed to validate permission asset: %s", record.Data.Asset)
	}

	// Aggregates all the permission and attestation grants the user has.
	for _, agreement := range record.Data.Agreements {
		now := time.Now()
		if !agreement.EffectiveAt.IsZero() && now.Before(agreement.EffectiveAt) {
			continue
		}

		if !agreement.ExpiresAt.IsZero() && now.After(agreement.ExpiresAt) {
			continue
		}

		switch agreement.Type {
		case "cloudevent":
			if _, ok := cloudEvtGrants[agreement.EventType]; !ok {
				cloudEvtGrants[agreement.EventType] = map[string]*set.StringSet{}
			}

			if _, ok := cloudEvtGrants[agreement.EventType][agreement.Source]; !ok {
				cloudEvtGrants[agreement.EventType][agreement.Source] = set.NewStringSet()
			}

			for _, id := range agreement.IDs {
				cloudEvtGrants[agreement.EventType][agreement.Source].Add(id)
			}

		case "permission":
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
