package autheval

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
)

const (
	TypeCloudEvent = "cloudevent"
	TypePermission = "permission"
)

type EventFilter struct {
	EventType string   `json:"eventType"`
	Source    string   `json:"source"`
	IDs       []string `json:"ids"`
	Tags      []string `json:"tags"`
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
func EvaluateCloudEvents(sacdAgreements CloudEventAgreements, cloudEvents []EventFilter) error {
	var err error
	for _, req := range cloudEvents {
		eventType := req.EventType
		if eventType == "" {
			eventType = tokenclaims.GlobalIdentifier
		}
		source := req.Source
		if source == "" {
			source = tokenclaims.GlobalIdentifier
		}
		ids := req.IDs
		if len(ids) == 0 {
			ids = []string{tokenclaims.GlobalIdentifier}
		}
		tags := req.Tags
		if len(tags) == 0 {
			tags = []string{tokenclaims.GlobalIdentifier}
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

// UserGrantMap extracts permission and CloudEvent grants from SACD data.
func UserGrantMap(data *models.SACDData, assetDID cloudevent.ERC721DID) (map[string]bool, CloudEventAgreements, error) {
	userPermGrants := make(map[string]bool)
	var cloudEvtAgreements CloudEventAgreements

	// Aggregates all the permission and attestation grants the user has.
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
		case TypeCloudEvent:
			cloudEvtAgreements.Add(agreement.EventType, agreement.Source, agreement.IDs, agreement.Tags)
		case TypePermission:
			// Add permissions from this agreement
			for _, permission := range agreement.Permissions {
				userPermGrants[permission.Name] = true
			}
		}
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
