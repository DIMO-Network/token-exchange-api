package autheval

import (
	"math/big"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
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
		name             string
		agreement        []models.Agreement
		request          []EventFilter
		expectedCEGrants func() map[string]map[string]*set.StringSet
		expectErr        bool
	}{
		{
			name: "Pass: request matches grant, all attestations",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("*")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						"*": gset,
					},
				}
			},
		},
		{
			name: "Pass: granted all attestations, asking for specific source",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("*")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						"*": gset,
					},
				}
			},
		},
		{
			name: "Pass: granted all attestations, asking for specific source and ids",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
					IDs:       []string{"1, 2, 3"},
				},
			},
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("*")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						"*": gset,
					},
				}
			},
		},
		{
			name: "Fail: not requesting any ids",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("1")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						common.BigToAddress(big.NewInt(1)).Hex(): gset,
					},
				}
			},
			expectErr: true,
		},
		{
			name: "Fail: not requesting source",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("1")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						common.BigToAddress(big.NewInt(1)).Hex(): gset,
					},
				}
			},
			expectErr: true,
		},
		{
			name: "Fail: source not valid hex address",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("1")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						"0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBd": gset,
					},
				}
			},
			expectErr: true,
		},
		{
			name: "Fail: permission not granted, address must match exactly",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				gset := set.NewStringSet()
				gset.Add("1")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						"0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBd": gset,
					},
				}
			},
			expectErr: true,
		},
		{
			name: "Pass: Asking for implicit grant (global) ",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"5", "6", "7"},
					Source:    tokenclaims.GlobalIdentifier,
				},
				{
					Type:      "cloudevent",
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				set1 := set.NewStringSet()
				set1.Add("1")
				set2 := set.NewStringSet()
				set2.Add("2")
				set3 := set.NewStringSet()
				set3.Add("5")
				set3.Add("6")
				set3.Add("7")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						common.BigToAddress(big.NewInt(1)).Hex(): set1,
						common.BigToAddress(big.NewInt(2)).Hex(): set2,
						tokenclaims.GlobalIdentifier:             set3,
					},
				}
			},
		},
		{
			name: "Pass: Asking for a source not specifically granted (global)",
			agreement: []models.Agreement{
				{
					Type:      "cloudevent",
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"5", "6", "7"},
					Source:    tokenclaims.GlobalIdentifier,
				},
				{
					Type:      "cloudevent",
					EventType: cloudevent.TypeAttestation,
					Asset:     "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
					IDs:       []string{"1"},
					Source:    common.BigToAddress(big.NewInt(1)).Hex(),
				},
				{
					Type:      "cloudevent",
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
			expectedCEGrants: func() map[string]map[string]*set.StringSet {
				set1 := set.NewStringSet()
				set1.Add("1")
				set2 := set.NewStringSet()
				set2.Add("2")
				set3 := set.NewStringSet()
				set3.Add("5")
				set3.Add("6")
				set3.Add("7")
				return map[string]map[string]*set.StringSet{
					cloudevent.TypeAttestation: {
						common.BigToAddress(big.NewInt(1)).Hex(): set1,
						common.BigToAddress(big.NewInt(2)).Hex(): set2,
						tokenclaims.GlobalIdentifier:             set3,
					},
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			permData.Agreements = tc.agreement
			expectedCEGrants := tc.expectedCEGrants()
			_, ceGrants, err := UserGrantMap(t.Context(), &permData, cloudevent.ERC721DID{
				ContractAddress: common.HexToAddress(nftCtrAddr),
				TokenID:         big.NewInt(123),
				ChainID:         1,
			}, nil)
			require.Nil(t, err)
			for eventType, evtMap := range expectedCEGrants {
				_, ok := ceGrants[eventType]
				require.True(t, ok)

				for src, vals := range evtMap {
					grantedIDs, ok := ceGrants[eventType][src]
					require.True(t, ok)

					for _, id := range grantedIDs.Slice() {
						require.Contains(t, vals.Slice(), id)
					}
				}
			}

			err = EvaluateCloudEvents(ceGrants, tc.request)
			if tc.expectErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
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
				"privilege:GetNonLocationHistory": true,
				"privilege:ExecuteCommands":       true,
				"privilege:GetCurrentLocation":    true,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  nil,
		},
		{
			name: "missing permission",
			userPermissions: map[string]bool{
				"privilege:GetNonLocationHistory": true,
				"privilege:ExecuteCommands":       true,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"}, // 3 is missing
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"privilege:GetCurrentLocation"},
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
		templatePermissions *template.PermissionsResult
		requestedPrivileges []string
		tokenID             int64
		nftContractAddress  string
		missingPermissions  []string
	}{
		{
			name: "active template with all permissions",
			userPermissions: map[string]bool{
				"privilege:GetNonLocationHistory": true,
				"privilege:ExecuteCommands":       true,
				"privilege:GetCurrentLocation":    true,
			},
			templatePermissions: &template.PermissionsResult{
				Permissions: map[string]bool{
					"privilege:GetNonLocationHistory": true,
					"privilege:ExecuteCommands":       true,
					"privilege:GetCurrentLocation":    true,
				},
				IsActive: true,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  nil,
		},
		{
			name: "active template with some permissions",
			userPermissions: map[string]bool{
				"privilege:GetNonLocationHistory": true,
				"privilege:ExecuteCommands":       true,
			},
			templatePermissions: &template.PermissionsResult{
				Permissions: map[string]bool{
					"privilege:GetNonLocationHistory": true,
					"privilege:ExecuteCommands":       true,
					"privilege:GetCurrentLocation":    true,
				},
				IsActive: true,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
		},
		{
			name: "inactive template with all permissions",
			userPermissions: map[string]bool{
				"privilege:GetNonLocationHistory": true,
				"privilege:ExecuteCommands":       true,
				"privilege:GetCurrentLocation":    true,
			},
			templatePermissions: &template.PermissionsResult{
				Permissions: map[string]bool{
					"privilege:GetNonLocationHistory": true,
					"privilege:ExecuteCommands":       true,
					"privilege:GetCurrentLocation":    true,
				},
				IsActive: false,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
		},
		{
			name: "inactive template with permissions not in SACD",
			userPermissions: map[string]bool{
				"privilege:GetNonLocationHistory": true,
			},
			templatePermissions: &template.PermissionsResult{
				Permissions: map[string]bool{
					"privilege:ExecuteCommands":    true,
					"privilege:GetCurrentLocation": true,
				},
				IsActive: false,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"privilege:GetNonLocationHistory", "privilege:ExecuteCommands", "privilege:GetCurrentLocation"},
		},
		{
			name: "SACD and template with only complementary permissions",
			userPermissions: map[string]bool{
				"privilege:GetNonLocationHistory": true,
				"privilege:AdditionalPermission":  true,
			},
			templatePermissions: &template.PermissionsResult{
				Permissions: map[string]bool{
					"privilege:ExecuteCommands":    true,
					"privilege:GetCurrentLocation": true,
				},
				IsActive: true,
			},
			requestedPrivileges: []string{"privilege:GetNonLocationHistory", "privilege:AdditionalPermission"},
			tokenID:             123,
			nftContractAddress:  "0x123",
			missingPermissions:  []string{"privilege:GetNonLocationHistory", "privilege:AdditionalPermission"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var matchPermissions map[string]bool

			match := matchTemplatePermissions(tc.userPermissions, tc.templatePermissions)
			if match {
				matchPermissions = tc.userPermissions
			}

			lacks := EvaluatePermissions(matchPermissions, tc.requestedPrivileges)
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
