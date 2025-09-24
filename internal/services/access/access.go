package access

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/autheval"
	"github.com/DIMO-Network/token-exchange-api/internal/constants"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/template"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	templatesvs "github.com/DIMO-Network/token-exchange-api/internal/services/template"
	"github.com/DIMO-Network/token-exchange-api/internal/signature"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
)

// privilege prefix to denote the 1:1 mapping to bit values and to make them easier to deprecate if desired in the future
var PrivilegeIDToName = constants.PrivilegeIDToName
var PrivilegeNameToID = constants.PrivilegeNameToID

type SACDInterface interface {
	CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address) (sacd.ISacdPermissionRecord, error)
	GetPermissions(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error)
}

type Template interface {
	Templates(opts *bind.CallOpts, templateID *big.Int) (template.ITemplateTemplateData, error)
	IsTemplateActive(opts *bind.CallOpts, templateID *big.Int) (bool, error)
}

type Erc1271Interface interface {
	IsValidSignature(opts *bind.CallOpts, hash [32]byte, signature []byte) ([4]byte, error)
}

type IPFSClient interface {
	GetValidSacdDoc(ctx context.Context, source string) (*cloudevent.RawEvent, error)
}

type TemplateService interface {
	GetTemplatePermissions(ctx context.Context, permissionTemplateID string, assetDID cloudevent.ERC721DID) (*templatesvs.PermissionsResult, error)
}

type SignatureValidator interface {
	ValidateSignature(ctx context.Context, payload json.RawMessage, signature string, ethAddr common.Address) (bool, error)
}

// NFTAccessRequest is a request to check access to an NFT.
type NFTAccessRequest struct {
	// Asset is the DID of the asset to check access to.
	Asset cloudevent.ERC721DID
	// Permissions is a list of the desired permissions.
	Permissions []string
	// EventFilters contains requests for access to CloudEvents attached to the specified NFT.
	EventFilters []autheval.EventFilter `json:"eventFilters"`
}
type Service struct {
	sacdContract    SACDInterface
	ipfsClient      IPFSClient
	templateService TemplateService
	sigValidator    SignatureValidator
}

func NewAccessService(ipfsService IPFSClient,
	sacd SACDInterface,
	templateService TemplateService,
	ethClient *ethclient.Client) (*Service, error) {
	return &Service{
		sacdContract:    sacd,
		ipfsClient:      ipfsService,
		sigValidator:    signature.NewValidator(ethClient),
		templateService: templateService,
	}, nil
}

func (s *Service) ValidateAccess(ctx context.Context, accessReq *NFTAccessRequest, ethAddr common.Address) error {
	err := s.ValidateAccessViaSourceDoc(ctx, accessReq, ethAddr)
	if err != nil {
		if len(accessReq.EventFilters) != 0 {
			return err
		}
		// TODO(elffjs): This is in debug for now because all prod grants are in an old format.
		logger := zerolog.Ctx(ctx)
		logger.Debug().Err(err).Msg("Failed to get valid SACD document, falling back to legacy permissions")
		return s.ValidateAccessViaRecord(ctx, accessReq, ethAddr) // fallback to legacy check if no event filters
	}
	return nil
}

func (s *Service) ValidateAccessViaSourceDoc(ctx context.Context, accessReq *NFTAccessRequest, ethAddr common.Address) error {
	opts := &bind.CallOpts{
		Context: ctx,
	}
	resPermRecord, err := s.sacdContract.CurrentPermissionRecord(opts, accessReq.Asset.ContractAddress, accessReq.Asset.TokenID, ethAddr)
	if err != nil {
		return richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to get permission record: %w", err),
			ExternalMsg: "failed to get permission record",
		}
	}

	record, err := s.ipfsClient.GetValidSacdDoc(ctx, resPermRecord.Source)
	if err != nil {
		return err
	}
	return s.evaluateSacdDoc(ctx, record, accessReq, ethAddr)
}

func (s *Service) evaluateSacdDoc(ctx context.Context, record *cloudevent.RawEvent, accessReq *NFTAccessRequest, grantee common.Address) error {
	var data models.SACDData
	if err := json.Unmarshal(record.Data, &data); err != nil {
		return richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to parse agreement data: %w", err),
			ExternalMsg: "failed to parse agreement data",
		}
	}

	if data.Grantee.Address != grantee.Hex() {
		return richerrors.Error{
			Code:        http.StatusUnauthorized,
			ExternalMsg: "Grantee address in permission record doesn't match requester",
		}
	}

	valid, err := s.sigValidator.ValidateSignature(ctx, record.Data, record.Signature, common.HexToAddress(data.Grantor.Address))
	if err != nil {
		return richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to validate grant signature: %w", err),
			ExternalMsg: "failed to validate grant signature",
		}
	}

	if !valid {
		return richerrors.Error{
			Code:        http.StatusForbidden,
			ExternalMsg: "invalid grant signature",
		}
	}

	userPermGrants, cloudEvtGrants, err := autheval.UserGrantMap(ctx, &data, accessReq.Asset, s.templateService)
	if err != nil {
		return richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to generate user grant map: %w", err),
			ExternalMsg: "failed to generate user grant map",
		}
	}

	if err := autheval.EvaluateCloudEvents(cloudEvtGrants, accessReq.EventFilters); err != nil {
		err = fmt.Errorf("failed to evaluate cloudevents: %w", err)
		return richerrors.Error{
			Code:        http.StatusForbidden,
			Err:         err,
			ExternalMsg: err.Error(),
		}
	}

	if lacks := autheval.EvaluatePermissions(userPermGrants, accessReq.Permissions); len(lacks) > 0 {
		return missingPermissionsError(grantee, accessReq.Asset, lacks)
	}
	return nil
}

func (s *Service) ValidateAccessViaRecord(ctx context.Context, accessReq *NFTAccessRequest, ethAddr common.Address) error {
	permBits := make([]int64, len(accessReq.Permissions))
	missing := make([]string, 0)
	for i, p := range accessReq.Permissions {
		var ok bool
		permBits[i], ok = PrivilegeNameToID[p]
		if !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return missingPermissionsError(ethAddr, accessReq.Asset, missing)
	}
	return s.evaluatePermissionsBits(ctx, accessReq.Asset, permBits, ethAddr)
}

// evaluatePermissionsBits checks if the user has the requested privileges using the on-chain permission bits system.
// It first checks permissions using the SACD contract's 2-bit permission system. If any permissions are missing,
// it falls back to checking the legacy MultiPrivilege contract. If all permissions are valid, it creates and returns
// a signed token.
//
// Parameters:
//   - c: The Fiber context for the HTTP request
//   - s: The SACD contract instance used to check permissions
//   - nftAddr: The Ethereum address of the NFT contract
//   - tokenReq: The permission token request containing token ID and requested privileges
//   - ethAddr: The Ethereum address of the user requesting permissions
//
// Returns:
//   - error: An error if the user lacks any requested permissions or if there's a system error,
//     otherwise nil if the token is successfully created and returned
func (s *Service) evaluatePermissionsBits(
	ctx context.Context,
	asset cloudevent.ERC721DID,
	permissions []int64,
	ethAddr common.Address,
) error {
	// Convert pr.Privileges to 2-bit array format
	mask, err := autheval.IntArrayTo2BitArray(permissions, 128) // Assuming max privilege is 128
	if err != nil {
		return richerrors.Error{
			Code:        http.StatusBadRequest,
			Err:         fmt.Errorf("failed to convert privileges to 2-bit array: %w", err),
			ExternalMsg: "Failed to convert privileges to 2-bit array",
		}
	}
	opts := &bind.CallOpts{
		Context: ctx,
	}
	ret, err := s.sacdContract.GetPermissions(opts, asset.ContractAddress, asset.TokenID, ethAddr, mask)
	if err != nil {
		return richerrors.Error{
			Code:        http.StatusInternalServerError,
			Err:         fmt.Errorf("failed to get permissions: %w", err),
			ExternalMsg: "Failed to get permissions",
		}
	}

	// Collecting these because in the future we'd like to list all of them.
	lack := autheval.EvaluatePermissionsBits(permissions, ret)

	if len(lack) != 0 {
		return missingPermissionsError(ethAddr, asset, lack)
	}

	return nil
}

func missingPermissionsError[T any](ethAddr common.Address, asset cloudevent.ERC721DID, lack []T) richerrors.Error {
	return richerrors.Error{
		Code:        http.StatusForbidden,
		ExternalMsg: fmt.Sprintf("Address %s lacks permissions %v for asset %s.", ethAddr.Hex(), lack, asset.String()),
	}
}
