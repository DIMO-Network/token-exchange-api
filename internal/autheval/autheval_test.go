package autheval

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	privilegemap "github.com/DIMO-Network/token-exchange-api/internal/constants"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services/template"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestEvaluateCloudEvents_Attestations(t *testing.T) {
	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")
	oneMinAgo := time.Now().Add(-1 * time.Minute)
	oneMinFuture := time.Now().Add(1 * time.Minute)

	permData := models.SACDData{
		Grantor: models.Address{
			Address: common.BigToAddress(big.NewInt(1)).Hex(),
		},
		Grantee: models.Address{
			Address: userEthAddr.Hex(),
		},
		EffectiveAt: oneMinAgo,
		ExpiresAt:   oneMinFuture,
		Asset:       "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
	}

	nftCtrAddr := "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"
	tests := []struct {
		name      string
		agreement []models.Agreement
		request   []EventFilter
		expectErr bool
	}{
		{
			name: "Pass: request matches grant, all attestations",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"*"},
				},
			},
		},
		{
			name: "Pass: granted all attestations, asking for specific source",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
					IDs:       []string{"*"},
				},
			},
		},
		{
			name: "Pass: granted all attestations, asking for specific source and ids",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
					IDs:       []string{"1", "2", "3"},
				},
			},
		},
		{
			name: "Fail: not requesting any ids",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
			},
			expectErr: true,
		},
		{
			name: "Fail: not requesting source",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					IDs:       []string{"1"},
				},
			},
			expectErr: true,
		},
		{
			name: "Fail: source not valid hex address",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    "0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBd",
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					IDs:       []string{"1"},
					Source:    "0x123",
				},
			},
			expectErr: true,
		},
		{
			name: "Fail: permission not granted, address must match exactly",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    "0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBd",
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					IDs:       []string{"1"},
					Source:    "0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBB",
				},
			},
			expectErr: true,
		},
		{
			name: "Pass: Asking for implicit grant (global) ",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"5", "6", "7"},
					Source:    tokenclaims.GlobalIdentifier,
				},
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"2"},
					Source:    common.BigToAddress(big.NewInt(2)).Hex(),
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					IDs:       []string{"5"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
			},
		},
		{
			name: "Pass: Asking for a source not specifically granted (global)",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"5", "6", "7"},
					Source:    tokenclaims.GlobalIdentifier,
				},
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
				{
					Type:      TypeCloudEvent,
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"2"},
					Source:    common.BigToAddress(big.NewInt(2)).Hex(),
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					IDs:       []string{"5"},
					Source:    common.BigToAddress(big.NewInt(6)).Hex(),
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			permData.Agreements = tc.agreement
			_, ceGrants, err := UserGrantMap(t.Context(), &permData, cloudevent.ERC721DID{
				ContractAddress: common.HexToAddress(nftCtrAddr),
				TokenID:         big.NewInt(123),
				ChainID:         1,
			}, nil)
			require.Nil(t, err)

			err = EvaluateCloudEvents(ceGrants, tc.request)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEvaluatePermissionsOnlySACD(t *testing.T) {
	tests := []struct {
		name                string
		userPermissions     map[string]bool
		requestedPrivileges []string
		tokenID             int64
		nftContractAddress  string
		missingPermissions  []string
	}{
		{
			name: "valid permissions - all granted",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				privilegemap.PrivilegeIDToName[2]: true,
				privilegemap.PrivilegeIDToName[3]: true,
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  nil,
		},
		{
			name: "missing permission",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				privilegemap.PrivilegeIDToName[2]: true,
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]}, // 3 is missing
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{privilegemap.PrivilegeIDToName[3]},
		},
		{
			name:                "unknown privilege ID",
			userPermissions:     map[string]bool{},
			requestedPrivileges: []string{"new-privilege"}, // 3 is missing
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"new-privilege"},
		},
		{
			name:                "empty privileges",
			userPermissions:     map[string]bool{},
			requestedPrivileges: []string{},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  nil,
		},
		{
			name:                "unknown privilege ID",
			userPermissions:     map[string]bool{},
			requestedPrivileges: []string{"new-privilege"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"new-privilege"},
		},
		{
			name:                "empty privileges",
			userPermissions:     map[string]bool{},
			requestedPrivileges: []string{},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lacks := EvaluatePermissions(tc.userPermissions, tc.requestedPrivileges)
			require.Equal(t, tc.missingPermissions, lacks)
		})
	}
}

func TestEvaluatePermissionsWithTemplate(t *testing.T) {
	tests := []struct {
		name                string
		userPermissions     map[string]bool
		templateSetup       func() *template.PermissionsResult
		requestedPrivileges []string
		tokenID             int64
		nftContractAddress  string
		missingPermissions  []string
		expectTemplateError bool
	}{
		{
			name: "ACTIVE template with all permissions, matching template and sacd assets",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				privilegemap.PrivilegeIDToName[2]: true,
				privilegemap.PrivilegeIDToName[3]: true,
			},
			templateSetup: func() *template.PermissionsResult {
				return &template.PermissionsResult{
					Permissions: map[string]bool{
						privilegemap.PrivilegeIDToName[1]: true,
						privilegemap.PrivilegeIDToName[2]: true,
						privilegemap.PrivilegeIDToName[3]: true,
					},
					IsActive: true,
				}
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  nil,
		},
		{
			name: "ACTIVE template with some permissions, matching template and sacd assets",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				privilegemap.PrivilegeIDToName[2]: true,
			},
			templateSetup: func() *template.PermissionsResult {
				return &template.PermissionsResult{
					Permissions: map[string]bool{
						privilegemap.PrivilegeIDToName[1]: true,
						privilegemap.PrivilegeIDToName[2]: true,
						privilegemap.PrivilegeIDToName[3]: true,
					},
					IsActive: true,
				}
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
		},
		{
			name: "ACTIVE template with all permissions, NOT matching template and sacd assets",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				privilegemap.PrivilegeIDToName[2]: true,
				privilegemap.PrivilegeIDToName[3]: true,
			},
			templateSetup: func() *template.PermissionsResult {
				return &template.PermissionsResult{
					Permissions: nil,
					IsActive:    false,
				}
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
		},
		{
			name: "INACTIVE template with all permissions, matching template and sacd assets",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				privilegemap.PrivilegeIDToName[2]: true,
				privilegemap.PrivilegeIDToName[3]: true,
			},
			templateSetup: func() *template.PermissionsResult {
				return &template.PermissionsResult{
					Permissions: map[string]bool{
						privilegemap.PrivilegeIDToName[1]: true,
						privilegemap.PrivilegeIDToName[2]: true,
						privilegemap.PrivilegeIDToName[3]: true,
					},
					IsActive: false,
				}
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
		},
		{
			name: "INACTIVE template with permissions not in SACD, matching template and sacd assets",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
			},
			templateSetup: func() *template.PermissionsResult {
				return &template.PermissionsResult{
					Permissions: map[string]bool{
						privilegemap.PrivilegeIDToName[2]: true,
						privilegemap.PrivilegeIDToName[3]: true,
					},
					IsActive: false,
				}
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{privilegemap.PrivilegeIDToName[1], privilegemap.PrivilegeIDToName[2], privilegemap.PrivilegeIDToName[3]},
		},
		{
			name: "SACD and template with only complementary permissions",
			userPermissions: map[string]bool{
				privilegemap.PrivilegeIDToName[1]: true,
				"privilege:AdditionalPermission":  true,
			},
			templateSetup: func() *template.PermissionsResult {
				return &template.PermissionsResult{
					Permissions: map[string]bool{
						privilegemap.PrivilegeIDToName[2]: true,
						privilegemap.PrivilegeIDToName[3]: true,
					},
					IsActive: true,
				}
			},
			requestedPrivileges: []string{privilegemap.PrivilegeIDToName[1], "privilege:AdditionalPermission"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{privilegemap.PrivilegeIDToName[1], "privilege:AdditionalPermission"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockTemplateService := &MockTemplateService{
				templateResult: tc.templateSetup(),
				shouldError:    tc.expectTemplateError,
			}

			sacdData := &models.SACDData{
				PermissionTemplateID: "123",
				Agreements: []models.Agreement{
					{
						Type:  "permission",
						Asset: "did:erc721:1:0x0000000000000000000000000000000000000123:123",
						Permissions: func() []models.Permission {
							perms := make([]models.Permission, 0, len(tc.userPermissions))
							for perm := range tc.userPermissions {
								perms = append(perms, models.Permission{Name: perm})
							}
							return perms
						}(),
					},
				},
			}

			assetDID := cloudevent.ERC721DID{
				ChainID:         1,
				ContractAddress: common.HexToAddress(tc.nftContractAddress),
				TokenID:         big.NewInt(tc.tokenID),
			}

			userPermGrants, _, err := UserGrantMap(t.Context(), sacdData, assetDID, mockTemplateService)

			if tc.expectTemplateError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			lacks := EvaluatePermissions(userPermGrants, tc.requestedPrivileges)
			require.Equal(t, tc.missingPermissions, lacks)
		})
	}
}

func TestEvaluatePermissionsBits(t *testing.T) {
	tests := []struct {
		name        string
		privileges  []int64
		bits        *big.Int
		expectedLen int // length of missing privileges
	}{
		{
			name:       "all privileges granted",
			privileges: []int64{1, 2, 3},
			bits: func() *big.Int {
				mask := big.NewInt(0)
				// Set bits for privileges 1, 2, 3
				mask.SetBit(mask, 2, 1) // privilege 1, bit 2
				mask.SetBit(mask, 3, 1) // privilege 1, bit 3
				mask.SetBit(mask, 4, 1) // privilege 2, bit 4
				mask.SetBit(mask, 5, 1) // privilege 2, bit 5
				mask.SetBit(mask, 6, 1) // privilege 3, bit 6
				mask.SetBit(mask, 7, 1) // privilege 3, bit 7
				return mask
			}(),
			expectedLen: 0,
		},
		{
			name:       "missing privilege",
			privileges: []int64{1, 2, 3},
			bits: func() *big.Int {
				mask := big.NewInt(0)
				// Set bits for privileges 1, 2 only
				mask.SetBit(mask, 2, 1) // privilege 1, bit 2
				mask.SetBit(mask, 3, 1) // privilege 1, bit 3
				mask.SetBit(mask, 4, 1) // privilege 2, bit 4
				mask.SetBit(mask, 5, 1) // privilege 2, bit 5
				// privilege 3 missing
				return mask
			}(),
			expectedLen: 1, // privilege 3 missing
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			missing := EvaluatePermissionsBits(tc.privileges, tc.bits)
			require.Equal(t, tc.expectedLen, len(missing))
		})
	}
}

func TestIntArrayTo2BitArray(t *testing.T) {
	tests := []struct {
		name        string
		indices     []int64
		length      int
		expectError bool
	}{
		{
			name:        "valid indices",
			indices:     []int64{1, 2, 3},
			length:      128,
			expectError: false,
		},
		{
			name:        "index out of range",
			indices:     []int64{1, 2, 128},
			length:      128,
			expectError: true,
		},
		{
			name:        "negative index",
			indices:     []int64{-1},
			length:      128,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := IntArrayTo2BitArray(tc.indices, tc.length)
			if tc.expectError {
				require.Error(t, err)
				require.Equal(t, big.NewInt(0), result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

// TestEvaluateCloudEvents_Comprehensive tests all cloud event functionality in logical groups
func TestEvaluateCloudEvents_Comprehensive(t *testing.T) {
	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")
	oneMinAgo := time.Now().Add(-1 * time.Minute)
	oneMinFuture := time.Now().Add(1 * time.Minute)

	permData := models.SACDData{
		Grantor: models.Address{
			Address: common.BigToAddress(big.NewInt(1)).Hex(),
		},
		Grantee: models.Address{
			Address: userEthAddr.Hex(),
		},
		EffectiveAt: oneMinAgo,
		ExpiresAt:   oneMinFuture,
		Asset:       "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
	}

	nftCtrAddr := "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"
	tests := []struct {
		name      string
		agreement []models.Agreement
		request   []EventFilter
		expectErr bool
	}{
		// === WILDCARD/GLOBAL MATCHING TESTS ===
		{
			name: "Pass: wildcard tags grant covers specific tag requests",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					Source:    "*",
					Tags:      []string{"*"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"*"},
					Tags:      []string{"diagnostics", "location"},
				},
			},
		},
		{
			name: "Pass: global event type grant covers any event type",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "*", // Global grant
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"*"},
				},
			},
			request: []EventFilter{
				{
					EventType: "any.custom.event.type",
					Source:    "*",
					IDs:       []string{"*"},
					Tags:      []string{"any-tag"},
				},
			},
		},
		{
			name: "Pass: empty fields default to global wildcards",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "*",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"*"},
				},
			},
			request: []EventFilter{
				{
					EventType: "", // Should default to "*"
					Source:    "", // Should default to "*"
					IDs:       []string{},
					Tags:      []string{},
				},
			},
		},

		// === SPECIFIC MATCHING TESTS ===
		{
			name: "Pass: specific tags match specific grants",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.fingerprint",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"security", "identity", "diagnostics"},
				},
			},
			request: []EventFilter{
				{
					EventType: "dimo.fingerprint",
					Source:    "*",
					IDs:       []string{"*"},
					Tags:      []string{"security", "diagnostics"},
				},
			},
		},
		{
			name: "Fail: requesting tag not granted",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "custom.vehicle.status",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"engine"},
				},
			},
			request: []EventFilter{
				{
					EventType: "custom.vehicle.status",
					Source:    "*",
					IDs:       []string{"*"},
					Tags:      []string{"battery"}, // Not granted
				},
			},
			expectErr: true,
		},
		{
			name: "Fail: requesting event type not granted",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"*"},
				},
			},
			request: []EventFilter{
				{
					EventType: "dimo.fingerprint", // Not granted
					Source:    "*",
					IDs:       []string{"*"},
					Tags:      []string{"*"},
				},
			},
			expectErr: true,
		},

		// === MULTI-AGREEMENT COMBINATIONS ===
		{
			name: "Pass: tags and IDs spanning multiple agreements",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1", "3"},
					Source:    "*",
					Tags:      []string{"diagnostics"},
				},
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1", "3"},
					Source:    "*",
					Tags:      []string{"location"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"1", "3"},
					Tags:      []string{"diagnostics", "location"},
				},
			},
		},
		{
			name: "Fail: missing tag-id combination across agreements",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    "*",
					Tags:      []string{"diagnostics"},
				},
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"2"},
					Source:    "*",
					Tags:      []string{"location"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"1"},
					Tags:      []string{"location"}, // ID 1 doesn't have location tag
				},
			},
			expectErr: true,
		},

		// === MULTI-REQUEST TESTS ===
		{
			name: "Pass: multiple event types in single request",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"diagnostics", "location"},
				},
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.fingerprint",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"security", "identity"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"1"},
					Tags:      []string{"diagnostics"},
				},
				{
					EventType: "dimo.fingerprint",
					Source:    "*",
					IDs:       []string{"2"},
					Tags:      []string{"security"},
				},
			},
		},
		{
			name: "Fail: one request in batch fails",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"diagnostics"},
				},
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.fingerprint",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"security"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"1"},
					Tags:      []string{"diagnostics"}, // This is granted
				},
				{
					EventType: "dimo.fingerprint",
					Source:    "*",
					IDs:       []string{"2"},
					Tags:      []string{"identity"}, // This is NOT granted
				},
			},
			expectErr: true,
		},

		// === EDGE CASES AND VALIDATION ===
		{
			name: "Pass: empty request array",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"*"},
					Source:    "*",
					Tags:      []string{"*"},
				},
			},
			request: []EventFilter{}, // Empty request should pass
		},
		{
			name:      "Fail: no agreements provided",
			agreement: []models.Agreement{}, // No agreements
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"*"},
					Tags:      []string{"*"},
				},
			},
			expectErr: true,
		},
		{
			name: "Pass: case sensitivity exact match",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"ABC123"},
					Source:    "*",
					Tags:      []string{"DiAgNoStIcS"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"ABC123"},      // Exact match
					Tags:      []string{"DiAgNoStIcS"}, // Exact match
				},
			},
		},
		{
			name: "Fail: case sensitivity mismatch",
			agreement: []models.Agreement{
				{
					Type:      TypeCloudEvent,
					EventType: "dimo.attestation",
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"ABC123"},
					Source:    "*",
					Tags:      []string{"diagnostics"},
				},
			},
			request: []EventFilter{
				{
					EventType: cloudevent.TypeAttestation,
					Source:    "*",
					IDs:       []string{"abc123"},      // Case mismatch
					Tags:      []string{"DIAGNOSTICS"}, // Case mismatch
				},
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			permData.Agreements = tc.agreement
			_, ceGrants, err := UserGrantMap(t.Context(), &permData, cloudevent.ERC721DID{
				ContractAddress: common.HexToAddress(nftCtrAddr),
				TokenID:         big.NewInt(123),
				ChainID:         1,
			}, nil)
			require.Nil(t, err)

			err = EvaluateCloudEvents(ceGrants, tc.request)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type MockTemplateService struct {
	templateResult *template.PermissionsResult
	shouldError    bool
}

func (m *MockTemplateService) GetTemplatePermissions(_ context.Context, _ string, _ cloudevent.ERC721DID) (*template.PermissionsResult, error) {
	if m.shouldError {
		return nil, fmt.Errorf("template service error")
	}
	return m.templateResult, nil
}
