package template

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/template"
	"github.com/DIMO-Network/token-exchange-api/internal/ipfsdoc"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/signature"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Template interface {
	Templates(opts *bind.CallOpts, templateID *big.Int) (template.ITemplateTemplateData, error)
}

type IPFSClient interface {
	Fetch(ctx context.Context, cid string) ([]byte, error)
}

type SignatureValidator interface {
	ValidateSignature(ctx context.Context, payload json.RawMessage, signature string, ethAddr common.Address) (bool, error)
}

type Service struct {
	templateContract Template
	ipfsClient       IPFSClient
	sigValidator     SignatureValidator

	// Cache for template data
	cacheMutex sync.RWMutex
	// templateID -> agreements list
	cache map[string][]models.TemplateAgreement
}

func NewTemplateService(templateContract Template, ipfsClient IPFSClient, ethClient *ethclient.Client) (*Service, error) {
	return &Service{
		templateContract: templateContract,
		ipfsClient:       ipfsClient,
		sigValidator:     signature.NewValidator(ethClient),
		cache:            make(map[string][]models.TemplateAgreement),
	}, nil
}

// GetTemplatePermissions fetches and validates template permissions
func (s *Service) GetTemplatePermissions(ctx context.Context, permissionTemplateID string, assetDID cloudevent.ERC721DID) (map[string]bool, error) {
	// Check cache first
	s.cacheMutex.RLock()
	if cachedAgreements, exists := s.cache[permissionTemplateID]; exists {
		s.cacheMutex.RUnlock()
		return s.extractPermissionsFromAgreements(cachedAgreements, assetDID), nil
	}
	s.cacheMutex.RUnlock()

	templateID, ok := big.NewInt(0).SetString(permissionTemplateID, 10)
	if !ok {
		return nil, fmt.Errorf("could not convert template ID string to big.Int")
	}

	opts := &bind.CallOpts{
		Context: ctx,
	}
	templateData, err := s.templateContract.Templates(opts, templateID)
	if err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusInternalServerError,
			Err:         fmt.Errorf("failed to get template data: %w", err),
			ExternalMsg: "Failed to get template data",
		}
	}

	// Fetch template document from IPFS
	rawEvent, err := ipfsdoc.GetValidSacdDoc(ctx, templateData.Source, s.ipfsClient)
	if err != nil {
		return nil, err
	}

	var data models.TemplateData
	if err := json.Unmarshal(rawEvent.Data, &data); err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to parse template data: %w", err),
			ExternalMsg: "failed to parse template data",
		}
	}

	// Validate template owner signature
	valid, err := s.sigValidator.ValidateSignature(ctx, rawEvent.Data, rawEvent.Signature, common.HexToAddress(data.Owner.Address))
	if err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to validate template owner signature: %w", err),
			ExternalMsg: "failed to validate template owner signature",
		}
	}

	if !valid {
		return nil, richerrors.Error{
			Code:        http.StatusForbidden,
			ExternalMsg: "invalid template owner signature",
		}
	}

	// Cache only the agreements
	s.cacheMutex.Lock()
	s.cache[permissionTemplateID] = data.Agreements
	s.cacheMutex.Unlock()

	templatePermGrants := s.extractPermissionsFromAgreements(data.Agreements, assetDID)
	return templatePermGrants, nil
}

func (s *Service) extractPermissionsFromAgreements(agreements []models.TemplateAgreement, assetDID cloudevent.ERC721DID) map[string]bool {
	templatePermGrants := make(map[string]bool)

	for _, agreement := range agreements {
		// TODO(lorran) agreement.Asset does not have :id, fix this if needed
		if agreement.Asset != assetDID.String() {
			// TODO(lorran) Consider if we want an error here
			continue
		}

		switch agreement.Type {
		case "permission":
			// Add permissions from this agreement
			for _, permission := range agreement.Permissions {
				templatePermGrants[permission.Name] = true
			}
		}
	}

	return templatePermGrants
}

// ClearCache for testing purposes
func (s *Service) ClearCache() {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()
	s.cache = make(map[string][]models.TemplateAgreement)
}

// GetCacheSize for testing purposes
func (s *Service) GetCacheSize() int {
	s.cacheMutex.RLock()
	defer s.cacheMutex.RUnlock()
	return len(s.cache)
}
