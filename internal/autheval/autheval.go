package autheval

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services/template"
)

type TemplateService interface {
	GetTemplatePermissions(ctx context.Context, permissionTemplateID string, assetDID cloudevent.ERC721DID) (*template.PermissionsResult, error)
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

// EvaluatePermissionsBits checks if user has privileges using 2-bit permission system.
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

// EvaluateCloudEvents validates all CloudEvent access requests against SACD agreements.
func EvaluateCloudEvents(sacdAgreements CloudEventAgreements, cloudEvents []models.EventFilter) error {
	var err error
	for _, req := range cloudEvents {
		eventType := req.EventType
		if eventType == "" {
			eventType = models.GlobalIdentifier
		}
		source := req.Source
		if source == "" {
			source = models.GlobalIdentifier
		}
		ids := req.IDs
		if len(ids) == 0 {
			ids = []string{models.GlobalIdentifier}
		}
		tags := req.Tags
		if len(tags) == 0 {
			tags = []string{models.GlobalIdentifier}
		}

		// Ids and tags can span across separate agreements so we need to check each combination
		for _, id := range ids {
			for _, tag := range tags {
				if !sacdAgreements.Grants(eventType, source, id, tag) {
					err = errors.Join(err, fmt.Errorf("lacking grant for requested cloud event {type: %s, source: %s, id: %s, tag: %s}", req.EventType, req.Source, id, tag))
				}
			}
		}
	}
	return err
}

// GetValidAgreements returns a map of sources to sets of valid IDs for a given CloudEvent type (`ceType`).
// global grants (applied to all events) and event-specific grants are merged
// input 'sacdAgreements' is a nested map: eventType -> source -> set of IDs.
func GetValidAgreements(sacdAgreements map[string]map[string]*set.StringSet, ceType string) map[string]*set.StringSet {
	agreementsBySource := make(map[string]*set.StringSet)
	eventGrants := sacdAgreements[ceType]
	globlaGrants := sacdAgreements[models.GlobalIdentifier]

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

// matchTemplatePermissions checks if SACD and template permissions matches based on template activation status
func matchTemplatePermissions(sacdPermissions map[string]bool, templateResult *template.PermissionsResult) bool {
	if templateResult == nil {
		return true
	}

	if templateResult.IsActive {
		// Template is active: check if permissions match
		// Check if SACD has all the permissions that the template has
		for templatePerm := range templateResult.Permissions {
			if !sacdPermissions[templatePerm] {
				return false
			}
		}

		return true
	}

	// Template is not active
	return false
}

// UserGrantMap extracts permission and CloudEvent grants from SACD data
func UserGrantMap(ctx context.Context, data *models.SACDData, assetDID cloudevent.ERC721DID, templateService TemplateService) (map[string]bool, CloudEventAgreements, error) {
	userPermGrants := make(map[string]bool)
	var cloudEvtAgreements CloudEventAgreements

	// Collect direct SACD permissions
	sacdPermissions := make(map[string]bool)
	var templateResult *template.PermissionsResult

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
			return nil, cloudEvtAgreements, fmt.Errorf("asset DID %s does not match request DID %s", agreement.Asset, assetDID.String())
		}

		switch agreement.Type {
		case models.TypeCloudEvent:
			cloudEvtAgreements.Add(agreement.EventType, agreement.Source, agreement.IDs, agreement.Tags)
		case models.TypePermission:
			// Add permissions from this agreement
			for _, permission := range agreement.Permissions {
				sacdPermissions[permission.Name] = true
			}
		}
	}

	if data.PermissionTemplateID != "" && data.PermissionTemplateID != "0" {
		var err error
		templateResult, err = templateService.GetTemplatePermissions(ctx, data.PermissionTemplateID, assetDID)
		if err != nil {
			return nil, cloudEvtAgreements, fmt.Errorf("failed to get template permissions: %w", err)
		}

		match := matchTemplatePermissions(sacdPermissions, templateResult)

		if match {
			userPermGrants = sacdPermissions
		}
	} else {
		// No template involved, use SACD permissions directly
		userPermGrants = sacdPermissions
	}

	return userPermGrants, cloudEvtAgreements, nil
}

// IntArrayTo2BitArray converts array of indices to 2-bit array representation.
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
