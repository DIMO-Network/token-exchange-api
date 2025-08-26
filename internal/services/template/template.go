package template

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

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

// TemplateInterface defines the contract interface for template operations
type TemplateInterface interface {
	Templates(opts *bind.CallOpts, templateId *big.Int) (template.ITemplateTemplateData, error)
}

// IPFSClient defines the interface for IPFS operations
type IPFSClient interface {
	Fetch(ctx context.Context, cid string) ([]byte, error)
}

// SignatureValidator defines the interface for signature validation
type SignatureValidator interface {
	ValidateSignature(ctx context.Context, payload json.RawMessage, signature string, ethAddr common.Address) (bool, error)
}

// Service handles template-related operations
type Service struct {
	templateContract TemplateInterface
	ipfsClient       IPFSClient
	sigValidator     SignatureValidator
}

// NewTemplateService creates a new template service
func NewTemplateService(templateContract TemplateInterface, ipfsClient IPFSClient, ethClient *ethclient.Client) (*Service, error) {
	return &Service{
		templateContract: templateContract,
		ipfsClient:       ipfsClient,
		sigValidator:     signature.NewValidator(ethClient),
	}, nil
}

// GetTemplatePermissions fetches and validates template permissions
func (s *Service) GetTemplatePermissions(ctx context.Context, permissionTemplateId string, assetDID cloudevent.ERC721DID) (map[string]bool, error) {
	templateId, ok := big.NewInt(0).SetString(permissionTemplateId, 10)
	if !ok {
		return nil, fmt.Errorf("could not convert template ID string to big.Int")
	}

	opts := &bind.CallOpts{
		Context: ctx,
	}
	templateData, err := s.templateContract.Templates(opts, templateId)
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

	// Extract permissions from template agreements
	templatePermGrants := make(map[string]bool)
	for _, agreement := range data.Agreements {
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

	return templatePermGrants, nil
}

// // TODO(lorran) move this to another package
// func (s *Service) getTemplatePermissions(ctx context.Context, permissionTemplateId string, assetDID cloudevent.ERC721DID) (map[string]bool, error) {
// 	templateId, ok := big.NewInt(0).SetString(permissionTemplateId, 10)
// 	if !ok {
// 		return nil, fmt.Errorf("could not convert tempalte ID string to big.Int")
// 	}

// 	opts := &bind.CallOpts{
// 		Context: ctx,
// 	}
// 	templateData, err := s.templateContract.Templates(opts, templateId)
// 	if err != nil {
// 		return nil, richerrors.Error{
// 			Code:        http.StatusInternalServerError,
// 			Err:         fmt.Errorf("failed to get template data: %w", err),
// 			ExternalMsg: "Failed to get template data",
// 		}
// 	}
// 	// TODO(lorran) check if Template JSON is in memory, if not, fetch from IPFS
// 	rawEvent, err := s.getValidSacdDoc(ctx, templateData.Source)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var data models.TemplateData
// 	if err := json.Unmarshal(rawEvent.Data, &data); err != nil {
// 		return nil, richerrors.Error{
// 			Code:        http.StatusUnauthorized,
// 			Err:         fmt.Errorf("failed to parse template data: %w", err),
// 			ExternalMsg: "failed to parse template data",
// 		}
// 	}

// 	valid, err := s.validateSignature(ctx, rawEvent.Data, rawEvent.Signature, common.HexToAddress(data.Owner.Address))
// 	if err != nil {
// 		return nil, richerrors.Error{
// 			Code:        http.StatusUnauthorized,
// 			Err:         fmt.Errorf("failed to validate template owner signature: %w", err),
// 			ExternalMsg: "failed to validate template owner signature",
// 		}
// 	}

// 	if !valid {
// 		return nil, richerrors.Error{
// 			Code:        http.StatusForbidden,
// 			ExternalMsg: "invalid template owner signature",
// 		}
// 	}

// 	templatePermGrants, err := autheval.TemplateGrantMap(data.Agreements, assetDID)
// 	if err != nil {
// 		return nil, richerrors.Error{
// 			Code:        http.StatusUnauthorized,
// 			Err:         fmt.Errorf("failed to generate user grant map: %w", err),
// 			ExternalMsg: "failed to generate user grant map",
// 		}
// 	}

// 	return templatePermGrants, nil
// }
