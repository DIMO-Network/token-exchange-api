package template

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/template"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

//go:generate go tool mockgen -source ./template.go -destination ./template_mock_test.go -package template
func TestTemplateService_CacheEffectiveness(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTemplateContract := NewMockTemplate(ctrl)
	mockIPFS := NewMockIPFSClient(ctrl)
	mockSigValidator := NewMockSignatureValidator(ctrl)

	service := &Service{
		templateContract: mockTemplateContract,
		ipfsClient:       mockIPFS,
		sigValidator:     mockSigValidator,
		cache:            make(map[string][]models.TemplateAgreement),
	}

	templateID := "123"
	assetDID := cloudevent.ERC721DID{
		ContractAddress: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		TokenID:         big.NewInt(1),
		ChainID:         1,
	}

	mockTemplateData := template.ITemplateTemplateData{
		Asset:       common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Permissions: big.NewInt(0),
		Source:      "ipfs://test-hash",
		IsActive:    true,
	}

	templateData := models.TemplateData{
		Agreements: []models.TemplateAgreement{
			{
				Type:  "permission",
				Asset: fmt.Sprintf("did:erc721:%d:%s", assetDID.ChainID, assetDID.ContractAddress.Hex()),
				Permissions: []models.Permission{
					{Name: "read:data"},
					{Name: "write:data"},
				},
			},
		},
	}

	ipfsRecord, _, err := signTemplateJSONHelper(&templateData)
	require.NoError(t, err)

	mockTemplateContract.EXPECT().
		Templates(gomock.Any(), big.NewInt(123)).
		Return(mockTemplateData, nil).
		Times(1) // Should only be called once due to

	mockTemplateContract.EXPECT().
		IsTemplateActive(gomock.Any(), big.NewInt(123)).
		Return(true, nil).
		Times(3) // Called each time to get current activation status

	mockIPFS.EXPECT().
		GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
		Return(ipfsRecord, nil).
		Times(1) // Should only be called once due to caching

	mockSigValidator.EXPECT().
		ValidateSignature(gomock.Any(), gomock.Any(), ipfsRecord.Signature, gomock.Any()).
		Return(true, nil).
		Times(1) // Should only be called once due to caching

	ctx := t.Context()

	// First call - should fetch from blockchain and IPFS
	assert.Equal(t, 0, service.GetCacheSize())
	perms1, err := service.GetTemplatePermissions(ctx, templateID, assetDID)
	require.NoError(t, err)
	assert.Equal(t, 1, service.GetCacheSize())

	expectedPerms := map[string]bool{
		"read:data":  true,
		"write:data": true,
	}
	assert.Equal(t, expectedPerms, perms1.Permissions)
	assert.True(t, perms1.IsActive)

	// Second call - should use cache (no additional mock expectations needed)
	perms2, err := service.GetTemplatePermissions(ctx, templateID, assetDID)
	require.NoError(t, err)
	assert.Equal(t, 1, service.GetCacheSize())
	assert.Equal(t, expectedPerms, perms2.Permissions)
	assert.True(t, perms2.IsActive)

	// Third call - should still use cache
	perms3, err := service.GetTemplatePermissions(ctx, templateID, assetDID)
	require.NoError(t, err)
	assert.Equal(t, 1, service.GetCacheSize())
	assert.Equal(t, expectedPerms, perms3.Permissions)
	assert.True(t, perms3.IsActive)

	// Test cache clearing
	service.ClearCache()
	assert.Equal(t, 0, service.GetCacheSize())
}

func TestGetTemplatePermissions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTemplateContract := NewMockTemplate(ctrl)
	mockIPFS := NewMockIPFSClient(ctrl)
	mockSigValidator := NewMockSignatureValidator(ctrl)

	service := &Service{
		templateContract: mockTemplateContract,
		ipfsClient:       mockIPFS,
		sigValidator:     mockSigValidator,
		cache:            make(map[string][]models.TemplateAgreement),
	}

	templateID := "123"
	assetDID := cloudevent.ERC721DID{
		ContractAddress: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		TokenID:         big.NewInt(1),
		ChainID:         1,
	}

	mockTemplateData := template.ITemplateTemplateData{
		Asset:       common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Permissions: big.NewInt(0),
		Source:      "ipfs://test-hash",
		IsActive:    true,
	}

	validTemplateData := models.TemplateData{
		Agreements: []models.TemplateAgreement{
			{
				Type:  "permission",
				Asset: fmt.Sprintf("did:erc721:%d:%s", assetDID.ChainID, assetDID.ContractAddress.Hex()),
				Permissions: []models.Permission{
					{Name: "read:data"},
					{Name: "write:data"},
				},
			},
		},
	}

	ipfsRecord, owner, err := signTemplateJSONHelper(&validTemplateData)
	require.NoError(t, err)

	tests := []struct {
		name           string
		setupMocks     func()
		expectedResult *PermissionsResult
		expectedError  bool
		errorContains  string
	}{
		{
			name: "successful template permission fetch",
			setupMocks: func() {
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(mockTemplateData, nil)
				mockIPFS.EXPECT().
					GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
					Return(ipfsRecord, nil)
				mockSigValidator.EXPECT().
					ValidateSignature(gomock.Any(), gomock.Any(), ipfsRecord.Signature, common.HexToAddress(owner.Address)).
					Return(true, nil)
				mockTemplateContract.EXPECT().
					IsTemplateActive(gomock.Any(), big.NewInt(123)).
					Return(true, nil)
			},
			expectedResult: &PermissionsResult{
				Permissions: map[string]bool{
					"read:data":  true,
					"write:data": true,
				},
				IsActive: true,
			},
			expectedError: false,
		},
		{
			name: "invalid signature",
			setupMocks: func() {
				record := *ipfsRecord
				record.Signature = "0xbad-signature"
				require.NoError(t, err)
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(mockTemplateData, nil)
				mockIPFS.EXPECT().
					GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
					Return(&record, nil)
				mockSigValidator.EXPECT().
					ValidateSignature(gomock.Any(), gomock.Any(), record.Signature, common.HexToAddress(owner.Address)).
					Return(false, nil)
			},
			expectedResult: nil,
			expectedError:  true,
			errorContains:  "invalid template owner signature",
		},
		{
			name: "signature validation error",
			setupMocks: func() {
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(mockTemplateData, nil)
				mockIPFS.EXPECT().
					GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
					Return(ipfsRecord, nil)
				mockSigValidator.EXPECT().
					ValidateSignature(gomock.Any(), gomock.Any(), ipfsRecord.Signature, common.HexToAddress(owner.Address)).
					Return(false, fmt.Errorf("signature validation failed"))
			},
			expectedResult: nil,
			expectedError:  true,
			errorContains:  "failed to validate template owner signature",
		},
		{
			name: "template contract error",
			setupMocks: func() {
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(template.ITemplateTemplateData{}, fmt.Errorf("contract call failed"))
			},
			expectedResult: nil,
			expectedError:  true,
			errorContains:  "failed to get template data",
		},
		{
			name: "IPFS fetch error",
			setupMocks: func() {
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(mockTemplateData, nil)
				mockIPFS.EXPECT().
					GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
					Return(nil, fmt.Errorf("IPFS fetch failed"))
			},
			expectedResult: nil,
			expectedError:  true,
			errorContains:  "IPFS fetch failed",
		},
		{
			name:           "invalid template ID",
			setupMocks:     func() {},
			expectedResult: nil,
			expectedError:  true,
			errorContains:  "could not convert template ID string to big.Int",
		},
		{
			name: "inactive template",
			setupMocks: func() {
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(mockTemplateData, nil)
				mockIPFS.EXPECT().
					GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
					Return(ipfsRecord, nil)
				mockSigValidator.EXPECT().
					ValidateSignature(gomock.Any(), gomock.Any(), ipfsRecord.Signature, common.HexToAddress(owner.Address)).
					Return(true, nil)
				mockTemplateContract.EXPECT().
					IsTemplateActive(gomock.Any(), big.NewInt(123)).
					Return(false, nil)
			},
			expectedResult: &PermissionsResult{
				Permissions: map[string]bool{
					"read:data":  true,
					"write:data": true,
				},
				IsActive: false,
			},
			expectedError: false,
		},
		{
			name: "template status check error",
			setupMocks: func() {
				mockTemplateContract.EXPECT().
					Templates(gomock.Any(), big.NewInt(123)).
					Return(mockTemplateData, nil)
				mockIPFS.EXPECT().
					GetValidSacdDoc(gomock.Any(), "ipfs://test-hash").
					Return(ipfsRecord, nil)
				mockSigValidator.EXPECT().
					ValidateSignature(gomock.Any(), gomock.Any(), ipfsRecord.Signature, common.HexToAddress(owner.Address)).
					Return(true, nil)
				mockTemplateContract.EXPECT().
					IsTemplateActive(gomock.Any(), big.NewInt(123)).
					Return(false, fmt.Errorf("status check failed"))
			},
			expectedResult: nil,
			expectedError:  true,
			errorContains:  "Failed to get template status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service.ClearCache()

			if tc.name == "invalid template ID" {
				result, err := service.GetTemplatePermissions(t.Context(), "invalid", assetDID)
				assert.Nil(t, result)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorContains)
			} else {
				tc.setupMocks()

				result, err := service.GetTemplatePermissions(t.Context(), templateID, assetDID)

				if tc.expectedError {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.errorContains)
					assert.Nil(t, result)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, result)
					assert.Equal(t, tc.expectedResult.IsActive, result.IsActive)

					assert.Equal(t, len(tc.expectedResult.Permissions), len(result.Permissions))
					for perm := range tc.expectedResult.Permissions {
						assert.True(t, result.Permissions[perm], "Expected permission %s not found", perm)
					}
				}
			}
		})
	}
}

func TestExtractPermissionsFromAgreements(t *testing.T) {
	service := &Service{
		cache: make(map[string][]models.TemplateAgreement),
	}

	tests := []struct {
		name       string
		agreements []models.TemplateAgreement
		assetDID   cloudevent.ERC721DID
		expected   map[string]bool
	}{
		{
			name: "valid agreements with matching asset",
			agreements: []models.TemplateAgreement{
				{
					Type:  "permission",
					Asset: "did:erc721:1:0x1234567890123456789012345678901234567890",
					Permissions: []models.Permission{
						{Name: "privilege:GetNonLocationHistory"},
						{Name: "privilege:ExecuteCommands"},
					},
				},
				{
					Type:  "permission",
					Asset: "did:erc721:1:0x1234567890123456789012345678901234567890",
					Permissions: []models.Permission{
						{Name: "privilege:GetCurrentLocation"},
					},
				},
			},
			assetDID: cloudevent.ERC721DID{
				ContractAddress: common.HexToAddress("0x1234567890123456789012345678901234567890"),
				TokenID:         big.NewInt(123),
				ChainID:         1,
			},
			expected: map[string]bool{
				"privilege:GetNonLocationHistory": true,
				"privilege:ExecuteCommands":       true,
				"privilege:GetCurrentLocation":    true,
			},
		},
		{
			name: "non-matching asset DID",
			agreements: []models.TemplateAgreement{
				{
					Type:  "permission",
					Asset: "did:erc721:1:0x1234567890123456789012345678901234567890",
					Permissions: []models.Permission{
						{Name: "privilege:GetNonLocationHistory"},
						{Name: "privilege:ExecuteCommands"},
					},
				},
			},
			assetDID: cloudevent.ERC721DID{
				ContractAddress: common.HexToAddress("0x0987654321098765432109876543210987654321"),
				TokenID:         big.NewInt(123),
				ChainID:         1,
			},
			expected: map[string]bool{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := service.extractPermissionsFromAgreements(tc.agreements, tc.assetDID)

			require.Equal(t, len(tc.expected), len(result), "Permission map length mismatch")

			for perm := range tc.expected {
				require.True(t, result[perm], "Expected permission %s not found or not granted", perm)
			}

			for perm := range result {
				require.True(t, tc.expected[perm], "Unexpected permission %s found in result", perm)
			}
		})
	}
}

func signTemplateJSONHelper(grantData *models.TemplateData) (*cloudevent.RawEvent, *models.Address, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("failed to derive public key")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	grantData.Owner = models.Address{
		Address: address.Hex(),
	}

	msgBytes, err := json.Marshal(grantData)
	if err != nil {
		return nil, nil, err
	}

	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msgBytes), msgBytes)

	hash := crypto.Keccak256Hash([]byte(prefixed))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, nil, err
	}

	signature[64] += 27

	var final cloudevent.RawEvent
	final.Signature = "0x" + common.Bytes2Hex(signature)

	final.Data = msgBytes
	final.Type = cloudevent.TypeSACDTemplate
	return &final, &grantData.Owner, nil
}
