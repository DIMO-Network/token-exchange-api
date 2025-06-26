package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func evaluateCloudEvents(sacdAgreements map[string]map[string]*set.StringSet, tokenReq *TokenRequest) error {
	var err error
	for _, req := range tokenReq.CloudEvents.Events {
		ceErr := evaluateCloudEvent(sacdAgreements, req)
		err = errors.Join(err, ceErr)
	}

	return err
}

// evaluateCloudEvent returns an error if CloudEvent access request is
// disallowed under the grants in the agreement map.
func evaluateCloudEvent(sacdAgreement map[string]map[string]*set.StringSet, req EventFilter) error {
	if !common.IsHexAddress(req.Source) && req.Source != tokenclaims.GlobalIdentifier {
		return fmt.Errorf("requested source %q invalid: must be %s or valid hex address", req.Source, tokenclaims.GlobalIdentifier)
	}

	if len(req.IDs) == 0 {
		return fmt.Errorf("must request at least one cloudevent id or global access request (%s)", tokenclaims.GlobalIdentifier)
	}

	grantedAggs := getValidAgreements(sacdAgreement, req.EventType)
	if len(grantedAggs) == 0 {
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

// getValidAgreements returns a map of sources to sets of valid IDs for a given CloudEvent type (`ceType`).
// global grants (applied to all events) and event-specific grants are merged
// input 'sacdAgreements' is a nested map: eventType -> source -> set of IDs.
func getValidAgreements(sacdAgreements map[string]map[string]*set.StringSet, ceType string) map[string]*set.StringSet {
	agreementsBySource := make(map[string]*set.StringSet)
	eventGrants := sacdAgreements[ceType]
	globlaGrants := sacdAgreements[tokenclaims.GlobalIdentifier]

	for source, ids := range eventGrants {
		agreementsBySource[source] = set.NewStringSet()

		for _, id := range ids.Slice() {
			agreementsBySource[source].Add(id)
		}

	}

	for source, ids := range globlaGrants {
		if _, ok := agreementsBySource[source]; !ok {
			agreementsBySource[source] = set.NewStringSet()
		}

		for _, id := range ids.Slice() {
			agreementsBySource[source].Add(id)
		}
	}

	return agreementsBySource
}

func evaluateIDsByGrantSource(globalGrants *set.StringSet, sourceGrants *set.StringSet, requestedIDs []string) []string {
	// Note that when the request is for the source "*" then these are the same set.
	grantsUnion := NewNilSafeUnion(globalGrants, sourceGrants)

	if grantsUnion.Contains(tokenclaims.GlobalIdentifier) {
		return nil
	}

	var missingIDs []string
	for _, reqID := range requestedIDs {
		if !grantsUnion.Contains(reqID) {
			missingIDs = append(missingIDs, reqID)
		}
	}
	return missingIDs
}

func userGrantMap(data *models.SACDData, nftContractAddr string, tokenID int64) (map[string]bool, map[string]map[string]*set.StringSet, error) {
	userPermGrants := make(map[string]bool)
	// type -> source -> ids
	cloudEvtGrants := make(map[string]map[string]*set.StringSet)

	// Aggregates all the permission and attestation grants the user has.
	for _, agreement := range data.Agreements {
		now := time.Now()
		if !agreement.EffectiveAt.IsZero() && now.Before(agreement.EffectiveAt) {
			continue
		}

		if !agreement.ExpiresAt.IsZero() && now.After(agreement.ExpiresAt) {
			continue
		}

		if err := validAssetDID(agreement.Asset, nftContractAddr, tokenID); err != nil {
			return nil, nil, fmt.Errorf("failed to validate agreement asset did %s: %w", data.Asset, err)
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

	if decodedDID.TokenID.Cmp(big.NewInt(tokenID)) != 0 {
		return fmt.Errorf("DID token id %d does not match request token id %d",
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

type NilSafeUnion struct {
	s1, s2 *set.StringSet
}

func NewNilSafeUnion(s1, s2 *set.StringSet) NilSafeUnion {
	return NilSafeUnion{s1: s1, s2: s2}
}

func (s *NilSafeUnion) Contains(x string) bool {
	return s.s1 != nil && s.s1.Contains(x) || s.s2 != nil && s.s2.Contains(x)
}

func validSignature(payload json.RawMessage, signature string, ethAddr common.Address) (bool, error) {
	sig := common.FromHex(signature)
	sig[64] -= 27

	hashWithPrfx := accounts.TextHash(payload)
	recoveredPubKey, err := crypto.SigToPub(hashWithPrfx, sig)
	if err != nil {
		return false, fmt.Errorf("failed to determine public key from signature: %w", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)
	return recoveredAddr == ethAddr, nil
}
