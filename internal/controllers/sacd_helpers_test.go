package controllers

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/set"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func Test_ValidSACDSignature(t *testing.T) {
	signer := common.HexToAddress("0xa9BC6E60EC5b541aED230d366073067F839EbB14")
	signedSACDWithPrefix := `{"specversion":"","timestamp":"0001-01-01T00:00:00Z","type":"","data":{"grantor":{"address":"0xa9BC6E60EC5b541aED230d366073067F839EbB14"},"grantee":{"address":"0x0000000000000000000000000000000000000001"},"effectiveAt":"0001-01-01T00:00:00Z","expiresAt":"0001-01-01T00:00:00Z","agreements":[{"type":"random-string","eventType":"random-string","ids":["a","b","c"],"effectiveAt":"0001-01-01T00:00:00Z","expiresAt":"0001-01-01T00:00:00Z","source":"random-string","asset":"","permissions":null}]},"signature":"0xf8f35c9faed52973bf5f6300b75813c1a8b3801515bfe2725401082f7ceaaa2477b141d237f47f1f3b9c64fb32808857a2fc562ffe97206238d20dbd71bdde2d1b"}`

	for _, test := range []struct {
		Name    string
		Payload string
	}{
		{
			Name:    "With Prefix",
			Payload: signedSACDWithPrefix,
		},
	} {

		var record models.SACDRecord
		err := json.Unmarshal([]byte(test.Payload), &record)
		require.NoError(t, err)

		res, err := validSignature(record.Data, record.Signature, signer)
		require.NoError(t, err)
		require.True(t, res)
	}

}

func signSACDHelper(grantData *models.SACDData) (*models.SACDRecord, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to derive public key")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	grantData.Grantor = models.Address{
		Address: address.Hex(),
	}

	msgBytes, err := json.Marshal(grantData)
	if err != nil {
		return nil, err
	}

	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msgBytes), msgBytes)

	hash := crypto.Keccak256Hash([]byte(prefixed))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	signature[64] += 27

	var final models.SACDRecord
	final.Signature = "0x" + common.Bytes2Hex(signature)
	final.Data = msgBytes
	final.Type = "dimo.sacd"
	// finalBytes, err := json.Marshal(final)
	return &final, nil
}
func TestTokenExchangeController_EvaluatingSACD_Attestations(t *testing.T) {
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
				CloudEvents: CloudEvents{
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
				CloudEvents: CloudEvents{
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
				CloudEvents: CloudEvents{
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
				CloudEvents: CloudEvents{
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
				CloudEvents: CloudEvents{
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
			err: fmt.Errorf("requested source \"\" invalid: must be * or valid hex address"),
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
				CloudEvents: CloudEvents{
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
			err: fmt.Errorf("requested source \"0x123\" invalid: must be * or valid hex address"),
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
				CloudEvents: CloudEvents{
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
				CloudEvents: CloudEvents{
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
				CloudEvents: CloudEvents{
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
			permData.Agreements = tc.agreement
			expectedCEGrants := tc.expectedCEGrants()
			_, ceGrants, err := userGrantMap(&permData)
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
