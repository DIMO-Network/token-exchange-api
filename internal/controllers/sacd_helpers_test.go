package controllers

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

const signedSACD = `{"specversion":"1.0","timestamp":"2025-03-11T14:30:00Z","type":"dimo.sacd","data":{"grantor":{"address":"0x07B584f6a7125491C991ca2a45ab9e641B1CeE1b","name":"Alice"},"grantee":{"address":"0x07B584f6a7125491C991ca2a45ab9e641B1CeE1b","name":"Bob"},"effectiveAt":"2025-03-11T14:30:00Z","expiresAt":"2030-12-20T05:20:45Z","asset":"did:erc721:80002:0x45fbCD3ef7361d156e8b16F5538AE36DEdf61Da8:928","additionalDates":{},"agreements":[{"type":"cloudevent","eventType":"dimo.attestation","source":"0x07B584f6a7125491C991ca2a45ab9e641B1CeE1b","ids":["unique-attestation-id-1","unique-attestation-id-2"],"effectiveAt":"2022-03-11T14:30:00Z","expiresAt":"2030-12-20T05:20:45Z"}],"extensions":{}},"signature":"0x92e576fbce2c2c29ede118c8e674d4aae6f1e606f5f84c3096fbe962840f3ec608a961d90c40c3331de13ba29ae4526498fe2eed5dfd4486c3f3e36fd97715631c"}`
const grantor = `0x07B584f6a7125491C991ca2a45ab9e641B1CeE1b`

func Test_ValidSACDSignature(t *testing.T) {
	var ipfs models.PermissionRecord
	err := json.Unmarshal([]byte(signedSACD), &ipfs)
	require.NoError(t, err)
	res, err := validSignature(ipfs.Data, ipfs.Signature, grantor)
	require.NoError(t, err)
	require.True(t, res)
}

func TestTokenExchangeController_EvaluatingSACD_Attestations(t *testing.T) {
	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")
	oneMinAgo := time.Now().Add(-1 * time.Minute)
	oneMinFuture := time.Now().Add(1 * time.Minute)

	grantData := models.PermissionData{
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

	ipfsRecord := models.PermissionRecord{
		Type: "dimo.sacd",
		// Data: grantDataBytes,
	}

	tests := []struct {
		name             string
		agreement        []models.Agreement
		request          TokenRequest
		expectedCEGrants func() map[string]map[string]*set.StringSet
		err              error
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							Source:    "*",
							IDs:       []string{"*"},
						},
					},
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							Source:    common.BigToAddress(big.NewInt(1)).Hex(),
							IDs:       []string{"*"},
						},
					},
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							Source:    common.BigToAddress(big.NewInt(1)).Hex(),
							IDs:       []string{"1, 2, 3"},
						},
					},
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							Source:    common.BigToAddress(big.NewInt(1)).Hex(),
						},
					},
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
			err: fmt.Errorf("must request at least one cloudevent id or global access request (*)"),
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							IDs:       []string{"1"},
						},
					},
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
			err: fmt.Errorf("requested source  invalid: must be * or valid hex address"),
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							IDs:       []string{"1"},
							Source:    "0x123",
						},
					},
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
			err: fmt.Errorf("requested source 0x123 invalid: must be * or valid hex address"),
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							IDs:       []string{"1"},
							Source:    "0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBB",
						},
					},
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
			err: fmt.Errorf("no dimo.attestation grants for source: 0xcce4eF41A67E28C3CF3dbc51a6CD3d004F53aCBB"),
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							IDs:       []string{"5"},
							Source:    common.BigToAddress(big.NewInt(1)).Hex(),
						},
					},
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
					cloudevent.TypeAttestation: map[string]*set.StringSet{
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
			request: TokenRequest{
				TokenID:            123,
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				CloudEvents: &CloudEvents{
					Events: []EventFilter{
						{
							EventType: cloudevent.TypeAttestation,
							IDs:       []string{"5"},
							Source:    common.BigToAddress(big.NewInt(6)).Hex(),
						},
					},
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
					cloudevent.TypeAttestation: map[string]*set.StringSet{
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
			grantData.Agreements = tc.agreement
			grantDataBytes, _ := json.Marshal(grantData)

			ipfsRecord.Data = grantDataBytes
			expectedCEGrants := tc.expectedCEGrants()
			_, ceGrants, err := userGrantMap(&grantData)
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

			err = evaluateCloudEvents(ceGrants, &tc.request)
			if tc.err != nil {
				require.NotNil(t, err)
				require.Equal(t, tc.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
			}
		})
	}
}
