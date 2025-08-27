package autheval

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services/template"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
)

type EventFilter struct {
	EventType string   `json:"eventType"`
	Source    string   `json:"source"`
	IDs       []string `json:"ids"`
}

type TemplateService interface {
	GetTemplatePermissions(ctx context.Context, permissionTemplateID string, assetDID cloudevent.ERC721DID) (*template.TemplatePermissionsResult, error)
}

// EvaluatePermissions checks if all requested privileges are present in the user permissions
// Returns slice of missing privileges if any are missing, or empty slice if all are valid
func EvaluatePermissions(userPermissions map[string]bool, requestedPrivileges []string) []string {
	// Check if all requested privileges are present in the permissions
	var missingPermissions []string

	for _, permName := range requestedPrivileges {

		// Check if the user has this permission
		if !userPermissions[permName] {
			missingPermissions = append(missingPermissions, permName)
		}
	}
	return missingPermissions
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

// combinePermissions combines SACD and template permissions based on template activation status
func combinePermissions(sacdPermissions map[string]bool, templateResult *template.TemplatePermissionsResult) map[string]bool {
	if templateResult == nil || len(templateResult.Permissions) == 0 {
		return sacdPermissions
	}

	resultPermissions := make(map[string]bool)

	if templateResult.IsActive {
		// Template is active: combine permissions
		// Check if SACD has the permissions that the template has
		for templatePerm := range templateResult.Permissions {
			if sacdPermissions[templatePerm] {
				resultPermissions[templatePerm] = true
			}
		}

		// Add additional permissions from SACD that are not in template
		for sacdPerm, granted := range sacdPermissions {
			if granted && !templateResult.Permissions[sacdPerm] {
				resultPermissions[sacdPerm] = true
			}
		}
	} else {
		// Template is not active: only additional SACD permissions are granted
		// Permissions in template that match SACD are NOT granted
		for sacdPerm, granted := range sacdPermissions {
			if granted && !templateResult.Permissions[sacdPerm] {
				resultPermissions[sacdPerm] = true
			}
		}
	}

	return resultPermissions
}

// UserGrantMap extracts permission and CloudEvent grants from SACD data
func UserGrantMap(ctx context.Context, data *models.SACDData, assetDID cloudevent.ERC721DID, templateService TemplateService) (map[string]bool, map[string]map[string]*set.StringSet, error) {
	// type -> source -> ids
	cloudEvtGrants := make(map[string]map[string]*set.StringSet)

	// Collect direct SACD permissions
	sacdPermissions := make(map[string]bool)
	var templateResult *template.TemplatePermissionsResult
	var hasTemplate bool

	// Single loop to process all agreements
	for _, agreement := range data.Agreements {
		now := time.Now()
		if !agreement.EffectiveAt.IsZero() && now.Before(agreement.EffectiveAt) {
			continue
		}

		if !agreement.ExpiresAt.IsZero() && now.After(agreement.ExpiresAt) {
			continue
		}

		if agreement.Asset != assetDID.String() {
			return nil, nil, fmt.Errorf("asset DID %s does not match request DID %s", agreement.Asset, assetDID.String())
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
			// Collect direct SACD permissions
			for _, permission := range agreement.Permissions {
				sacdPermissions[permission.Name] = true
			}

			// Handle template if present
			if agreement.PermissionTemplateID != "" && agreement.PermissionTemplateID != "0" && !hasTemplate {
				var err error
				templateResult, err = templateService.GetTemplatePermissions(ctx, agreement.PermissionTemplateID, assetDID)
				if err != nil {
					// TODO(lorran) I don't think we want to return here
					return nil, nil, fmt.Errorf("failed to get template permissions: %w", err)
				}
				hasTemplate = true
			}
		}
	}

	var userPermGrants map[string]bool
	// Combine permissions using the autheval package logic
	if hasTemplate {
		userPermGrants = combinePermissions(sacdPermissions, templateResult)
	} else {
		// No template involved, use SACD permissions directly
		userPermGrants = sacdPermissions
	}

	return userPermGrants, cloudEvtGrants, nil
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
