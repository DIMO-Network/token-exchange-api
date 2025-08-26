package template

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/template"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

//go:generate go tool mockgen -source ./template.go -destination ./template_mock_test.go -package template
func TestTemplateService_CacheEffectiveness(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTemplateContract := NewMockTemplateInterface(ctrl)
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

	// Mock template data
	mockTemplateData := template.ITemplateTemplateData{
		Asset:       common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Permissions: big.NewInt(0),
		Source:      "ipfs://test-hash",
		IsActive:    true,
	}

	// Mock IPFS document
	templateData := models.TemplateData{
		Owner: models.Address{Address: "0x1111111111111111111111111111111111111111"},
		Agreements: []models.TemplateAgreement{
			{
				Type:  "permission",
				Asset: assetDID.String(),
				Permissions: []models.Permission{
					{Name: "read:data"},
					{Name: "write:data"},
				},
			},
		},
	}

	templateDataBytes, err := json.Marshal(templateData)
	require.NoError(t, err)

	var rawEvent cloudevent.RawEvent
	rawEvent.Type = "dimo.sacd.template"
	rawEvent.Data = templateDataBytes
	rawEvent.Signature = "0x1234567890abcdef"

	ipfsDoc, err := json.Marshal(rawEvent)
	require.NoError(t, err)

	// Set up mock expectations for the first call only
	mockTemplateContract.EXPECT().
		Templates(gomock.Any(), big.NewInt(123)).
		Return(mockTemplateData, nil).
		Times(1) // Should only be called once due to caching

	mockIPFS.EXPECT().
		Fetch(gomock.Any(), "ipfs://test-hash").
		Return(ipfsDoc, nil).
		Times(1) // Should only be called once due to caching

	mockSigValidator.EXPECT().
		ValidateSignature(gomock.Any(), gomock.Any(), "0x1234567890abcdef", gomock.Any()).
		Return(true, nil).
		Times(1) // Should only be called once due to caching

	ctx := context.Background()

	// First call - should fetch from blockchain and IPFS
	assert.Equal(t, 0, service.GetCacheSize())
	perms1, err := service.GetTemplatePermissions(ctx, templateID, assetDID)
	require.NoError(t, err)
	assert.Equal(t, 1, service.GetCacheSize())

	expectedPerms := map[string]bool{
		"read:data":  true,
		"write:data": true,
	}
	assert.Equal(t, expectedPerms, perms1)

	// Second call - should use cache (no additional mock expectations needed)
	perms2, err := service.GetTemplatePermissions(ctx, templateID, assetDID)
	require.NoError(t, err)
	assert.Equal(t, 1, service.GetCacheSize())
	assert.Equal(t, expectedPerms, perms2)

	// Third call - should still use cache
	perms3, err := service.GetTemplatePermissions(ctx, templateID, assetDID)
	require.NoError(t, err)
	assert.Equal(t, 1, service.GetCacheSize())
	assert.Equal(t, expectedPerms, perms3)

	// Test cache clearing
	service.ClearCache()
	assert.Equal(t, 0, service.GetCacheSize())
}
