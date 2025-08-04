package autheval

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

// privilege prefix to denote the 1:1 mapping to bit values and to make them easier to deprecate if desired in the future
var PermissionMap = map[int]string{
	1: "privilege:GetNonLocationHistory",  // All-time non-location data
	2: "privilege:ExecuteCommands",        // Commands
	3: "privilege:GetCurrentLocation",     // Current location
	4: "privilege:GetLocationHistory",     // All-time location
	5: "privilege:GetVINCredential",       // View VIN credential
	6: "privilege:GetLiveData",            // Subscribe live data
	7: "privilege:GetRawData",             // Raw data
	8: "privilege:GetApproximateLocation", // Approximate location
}

type EventFilter struct {
	EventType string   `json:"eventType"`
	Source    string   `json:"source"`
	IDs       []string `json:"ids"`
}

// EvaluatePermissions checks if all requested privileges are present in the user permissions
func EvaluatePermissions(userPermissions map[string]bool, requestedPrivileges []int64, tokenID int64, nftContractAddress string) error {
	// Check if all requested privileges are present in the permissions
	var missingPermissions []int64

	for _, privID := range requestedPrivileges {
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
		return fmt.Errorf("missing permissions: %v on token id %d for asset %s", missingPermissions, tokenID, nftContractAddress)
	}

	// If we get here, all permissions are valid
	return nil
}

// EvaluatePermissionsBits checks if user has privileges using 2-bit permission system
// Returns slice of missing privileges if any are missing, or empty slice if all are valid
func EvaluatePermissionsBits(privileges []int64, permissionBits *big.Int) []int64 {
	var lack []int64

	for _, p := range privileges {
		if permissionBits.Bit(2*int(p)) != 1 || permissionBits.Bit(2*int(p)+1) != 1 {
			lack = append(lack, p)
		}
	}

	return lack
}

// EvaluateCloudEvents validates all CloudEvent access requests against SACD agreements
func EvaluateCloudEvents(sacdAgreements map[string]map[string]*set.StringSet, cloudEvents []EventFilter) error {
	var err error
	for _, req := range cloudEvents {
		ceErr := EvaluateCloudEvent(sacdAgreements, req)
		err = errors.Join(err, ceErr)
	}

	return err
}

// EvaluateCloudEvent returns an error if CloudEvent access request is
// disallowed under the grants in the agreement map.
func EvaluateCloudEvent(sacdAgreement map[string]map[string]*set.StringSet, req EventFilter) error {
	if !common.IsHexAddress(req.Source) && req.Source != tokenclaims.GlobalIdentifier {
		return fmt.Errorf("requested source %q invalid: must be %s or valid hex address", req.Source, tokenclaims.GlobalIdentifier)
	}

	if len(req.IDs) == 0 {
		return fmt.Errorf("must request at least one cloudevent id or global access request (%s)", tokenclaims.GlobalIdentifier)
	}

	grantedAggs := GetValidAgreements(sacdAgreement, req.EventType)
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

	if missingIDs := EvaluateIDsByGrantSource(globalGrantIDs, sourceGrantIDs, req.IDs); len(missingIDs) > 0 {
		return fmt.Errorf("lacking %s grant for source %s with ids: %s", req.EventType, req.Source, strings.Join(missingIDs, ","))
	}

	return nil
}

// GetValidAgreements returns a map of sources to sets of valid IDs for a given CloudEvent type (`ceType`).
// global grants (applied to all events) and event-specific grants are merged
// input 'sacdAgreements' is a nested map: eventType -> source -> set of IDs.
func GetValidAgreements(sacdAgreements map[string]map[string]*set.StringSet, ceType string) map[string]*set.StringSet {
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

// EvaluateIDsByGrantSource checks if requested IDs are covered by grants
func EvaluateIDsByGrantSource(globalGrants *set.StringSet, sourceGrants *set.StringSet, requestedIDs []string) []string {
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

// UserGrantMap extracts permission and CloudEvent grants from SACD data
func UserGrantMap(data *models.SACDData, nftContractAddr string, tokenID int64) (map[string]bool, map[string]map[string]*set.StringSet, error) {
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

		if err := ValidAssetDID(agreement.Asset, nftContractAddr, tokenID); err != nil {
			return nil, nil, fmt.Errorf("failed to validate agreement asset did %s: %w", agreement.Asset, err)
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

// ValidAssetDID verifies that the provided DID matches the NFT contract address
// and token ID specified in the permission token request.
func ValidAssetDID(did string, nftContractAddr string, tokenID int64) error {
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

// IntArrayTo2BitArray converts array of indices to 2-bit array representation
func IntArrayTo2BitArray(indices []int64, length int) (*big.Int, error) {
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

// NilSafeUnion represents a union of two string sets that handles nil values safely
type NilSafeUnion struct {
	s1, s2 *set.StringSet
}

// NewNilSafeUnion creates a new NilSafeUnion from two string sets
func NewNilSafeUnion(s1, s2 *set.StringSet) NilSafeUnion {
	return NilSafeUnion{s1: s1, s2: s2}
}

// Contains checks if the union contains the given string
func (s *NilSafeUnion) Contains(x string) bool {
	return s.s1 != nil && s.s1.Contains(x) || s.s2 != nil && s.s2.Contains(x)
}

// ValidSignature validates signature for SACD documents
func ValidSignature(payload json.RawMessage, signature string, ethAddr common.Address) (bool, error) {
	if signature == "" {
		return false, errors.New("empty signature")
	}

	sig := common.FromHex(signature)
	if len(sig) != 65 {
		return false, fmt.Errorf("invalid signature length: %d", len(sig))
	}

	sig[64] -= 27
	hashWithPrfx := accounts.TextHash(payload)
	recoveredPubKey, err := crypto.SigToPub(hashWithPrfx, sig)
	if err != nil {
		return false, fmt.Errorf("failed to determine public key from signature: %w", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)
	return recoveredAddr == ethAddr, nil
}
