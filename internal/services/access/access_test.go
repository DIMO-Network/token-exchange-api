package access

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/autheval"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services/template"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

//go:generate go tool mockgen -source ./access.go -destination ./access_mock_test.go -package access
func TestAccessService_ValidateAccess(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockSacd := NewMockSACDInterface(mockCtrl)
	mockTemplate := NewMockTemplate(mockCtrl)
	mockipfs := NewMockIPFSClient(mockCtrl)
	mockSigValidator := NewMockSignatureValidator(mockCtrl)

	templateService, err := template.NewTemplateService(mockTemplate, mockipfs, nil)
	require.NoError(t, err)

	accessService, err := NewAccessService(mockipfs, mockSacd, templateService, nil)
	require.NoError(t, err)
	accessService.sigValidator = mockSigValidator

	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	devLicenseAddr := common.HexToAddress("0x69F5C4D08F6bC8cD29fE5f004d46FB566270868d")

	effectiveAt := time.Now().Add(-5 * time.Hour)
	expiresAt := time.Now().Add(5 * time.Hour)

	permData := models.SACDData{
		Grantee: models.Address{
			Address: userEthAddr.Hex(),
		},
		EffectiveAt: time.Now().Add(-5 * time.Hour),
		ExpiresAt:   time.Now().Add(5 * time.Hour),
		Asset:       "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
		Agreements: []models.Agreement{
			{
				Type:                 "cloudevent",
				EffectiveAt:          effectiveAt,
				ExpiresAt:            expiresAt,
				EventType:            cloudevent.TypeAttestation,
				PermissionTemplateID: "", // TODO(lorran) create mock template ID
				Source:               common.BigToAddress(big.NewInt(1)).Hex(),
				IDs:                  []string{"1"},
				Asset:                "did:erc721:1:0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144:123",
			},
		},
	}

	ipfsRecord, err := signSACDHelper(&permData)
	require.NoError(t, err)

	ipfsBytes, err := json.Marshal(ipfsRecord)
	require.NoError(t, err)

	// Create a mock empty permission record to return
	emptyPermRecord := sacd.ISacdPermissionRecord{
		Permissions: big.NewInt(0),
		Expiration:  big.NewInt(0),
		Source:      "",
	}

	tests := []struct {
		name            string
		ethAddr         common.Address
		accessRequest   *NFTAccessRequest
		mockSetup       func(t *testing.T)
		expectedErrCode int
	}{
		{
			name:    "valid request with single privilege and no SACD document or event filters",
			ethAddr: devLicenseAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				Permissions: []string{PrivilegeIDToName[4]},
			},
			mockSetup: func(*testing.T) {
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), devLicenseAddr).Return(emptyPermRecord, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				mockSacd.EXPECT().GetPermissions(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), devLicenseAddr, big.NewInt(0b1100000000)).Return(big.NewInt(0b1100000000), nil)
			}},
		{
			name:    "valid request with multiple privileges and no SACD document or event filters",
			ethAddr: userEthAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				Permissions: []string{PrivilegeIDToName[1], PrivilegeIDToName[2], PrivilegeIDToName[4], PrivilegeIDToName[5]},
			},
			mockSetup: func(*testing.T) {
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b111100111100)).Return(big.NewInt(0b111100111100), nil)
			}},
		{
			name:    "missing privilege request with multiple privileges and no SACD document or event filters",
			ethAddr: userEthAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				Permissions: []string{PrivilegeIDToName[1], PrivilegeIDToName[2], PrivilegeIDToName[4], PrivilegeIDToName[5]},
			},
			mockSetup: func(*testing.T) {
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b111100111100)).Return(big.NewInt(0b111100001100), nil)

			},
			expectedErrCode: fiber.StatusForbidden,
		},
		{
			name:    "valid sacd",
			ethAddr: userEthAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				EventFilters: []autheval.EventFilter{
					{
						EventType: cloudevent.TypeAttestation,
						Source:    common.BigToAddress(big.NewInt(1)).Hex(),
						IDs:       []string{"1"},
					},
				},
			},

			mockSetup: func(*testing.T) {
				permRecord := sacd.ISacdPermissionRecord{
					Permissions: big.NewInt(0),
					Expiration:  big.NewInt(0),
					Source:      "test-source",
				}
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(permRecord, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), permRecord.Source).Return(ipfsBytes, nil)
				mockSigValidator.EXPECT().ValidateSignature(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			},
		},
		{
			name:    "invalid sacd signature",
			ethAddr: userEthAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				EventFilters: []autheval.EventFilter{
					{
						EventType: cloudevent.TypeAttestation,
						Source:    common.BigToAddress(big.NewInt(1)).Hex(),
						IDs:       []string{"1"},
					},
				},
			},

			mockSetup: func(*testing.T) {
				permRecord := sacd.ISacdPermissionRecord{
					Permissions: big.NewInt(0),
					Expiration:  big.NewInt(0),
					Source:      "test-source",
				}
				record := *ipfsRecord
				record.Signature = "0xbad-signature"
				ipfsByte, err := json.Marshal(record)
				require.NoError(t, err)
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(permRecord, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), permRecord.Source).Return(ipfsByte, nil)
				mockSigValidator.EXPECT().ValidateSignature(gomock.Any(), gomock.Any(), "0xbad-signature", gomock.Any()).Return(false, nil)
			},
			expectedErrCode: fiber.StatusForbidden,
		},
		{
			name:    "invalid recover signature valid erc1271",
			ethAddr: userEthAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				EventFilters: []autheval.EventFilter{
					{
						EventType: cloudevent.TypeAttestation,
						Source:    common.BigToAddress(big.NewInt(1)).Hex(),
						IDs:       []string{"1"},
					},
				},
			},

			mockSetup: func(*testing.T) {
				permRecord := sacd.ISacdPermissionRecord{
					Permissions: big.NewInt(0),
					Expiration:  big.NewInt(0),
					Source:      "test-source",
				}
				record := *ipfsRecord
				record.Signature = "0xbad-signature"
				ipfsBytes, err := json.Marshal(record)
				require.NoError(t, err)
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(permRecord, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), permRecord.Source).Return(ipfsBytes, nil)
				mockSigValidator.EXPECT().ValidateSignature(gomock.Any(), gomock.Any(), "0xbad-signature", gomock.Any()).Return(true, nil)
			},
		},
		{
			name:    "Fail: must pass privilege or cloud event request",
			ethAddr: userEthAddr,
			accessRequest: &NFTAccessRequest{
				Asset: cloudevent.ERC721DID{
					ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
					TokenID:         big.NewInt(123),
					ChainID:         1,
				},
				EventFilters: []autheval.EventFilter{
					{},
				},
			},
			mockSetup: func(*testing.T) {
				mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(ipfsBytes, nil)
				mockSigValidator.EXPECT().ValidateSignature(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			},
			expectedErrCode: fiber.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.mockSetup(t)
			err := accessService.ValidateAccess(t.Context(), tc.accessRequest, tc.ethAddr)
			if tc.expectedErrCode == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var richErr richerrors.Error
			require.ErrorAs(t, err, &richErr)
			require.Equal(t, tc.expectedErrCode, richErr.Code)
		})
	}
}

func signSACDHelper(grantData *models.SACDData) (*cloudevent.RawEvent, error) {
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

	var final cloudevent.RawEvent
	final.Signature = "0x" + common.Bytes2Hex(signature)

	final.Data = msgBytes
	final.Type = "dimo.sacd"
	return &final, nil
}
