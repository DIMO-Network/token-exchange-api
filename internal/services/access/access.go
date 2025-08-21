package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/autheval"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/erc1271"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/template"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
)

var erc1271magicValue = [4]byte{0x16, 0x26, 0xba, 0x7e}

// privilege prefix to denote the 1:1 mapping to bit values and to make them easier to deprecate if desired in the future
var PrivilegeIDToName = map[int64]string{
	1: "privilege:GetNonLocationHistory",  // All-time non-location data
	2: "privilege:ExecuteCommands",        // Commands
	3: "privilege:GetCurrentLocation",     // Current location
	4: "privilege:GetLocationHistory",     // All-time location
	5: "privilege:GetVINCredential",       // View VIN credential
	6: "privilege:GetLiveData",            // Subscribe live data
	7: "privilege:GetRawData",             // Raw data
	8: "privilege:GetApproximateLocation", // Approximate location
}

var PrivilegeNameToID = func() map[string]int64 {
	privMap := make(map[string]int64, len(PrivilegeIDToName))
	for id, name := range PrivilegeIDToName {
		privMap[name] = id
	}
	return privMap
}()

type SACDInterface interface {
	CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address) (sacd.ISacdPermissionRecord, error)
	GetPermissions(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error)
}

type TemplateInterface interface {
	Templates(opts *bind.CallOpts, templateId *big.Int) (template.ITemplateTemplateData, error)
}

type erc1271Mgr interface {
	NewErc1271(address common.Address, backend bind.ContractBackend) (Erc1271Interface, error)
}
type Erc1271Interface interface {
	IsValidSignature(opts *bind.CallOpts, hash [32]byte, signature []byte) ([4]byte, error)
}

type defaultErc1271Factory struct{}

func (f *defaultErc1271Factory) NewErc1271(address common.Address, backend bind.ContractBackend) (Erc1271Interface, error) {
	return erc1271.NewErc1271(address, backend)
}

type IPFSClient interface {
	Fetch(ctx context.Context, cid string) ([]byte, error)
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
	sacdContract     SACDInterface
	templateContract TemplateInterface
	ipfsClient       IPFSClient
	ethClient        *ethclient.Client
	// I don't like this, but it's the only way to get the mock to work.
	erc1271Mgr erc1271Mgr
}

func NewAccessService(ipfsService IPFSClient,
	sacd SACDInterface,
	template TemplateInterface,
	ethClient *ethclient.Client) (*Service, error) {
	return &Service{
		sacdContract: sacd,
		ipfsClient:   ipfsService,
		ethClient:    ethClient,
		erc1271Mgr:   &defaultErc1271Factory{},
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

	record, err := s.getValidSacdDoc(ctx, resPermRecord.Source)
	if err != nil {
		return err
	}
	return s.evaluateSacdDoc(ctx, record, accessReq, ethAddr)
}

// getValidSacdDoc fetches and validates a SACD from IPFS.
// It retrieves the document using the provided source identifier, attempts to parse it as JSON,
// and verifies that it has the correct type for a DIMO SACD document.
//
// Parameters:
//   - ctx: The context for the IPFS request, which can be used for cancellation and timeouts
//   - source: The IPFS content identifier (CID) for the SACD document, typically with an "ipfs://" prefix
//
// Returns:
//   - *cloudevent.RawEvent: A pointer to the parsed raw cloud event if valid, or nil if the document
//     could not be fetched, parsed, or doesn't have the correct type
func (s *Service) getValidSacdDoc(ctx context.Context, source string) (*cloudevent.RawEvent, error) {
	sacdDoc, err := s.ipfsClient.Fetch(ctx, source)
	if err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to fetch source document from IPFS: %w", err),
			ExternalMsg: "failed to fetch source document from IPFS",
		}
	}

	var record cloudevent.RawEvent
	if err := json.Unmarshal(sacdDoc, &record); err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to parse sacd data: %w", err),
			ExternalMsg: "failed to parse sacd data",
		}
	}

	if record.Type != "dimo.sacd" && record.Type != "dimo.sacd.template" {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			ExternalMsg: fmt.Sprintf("invalid type: expected 'dimo.sacd' or 'dimo.sacd.template', got '%s'", record.Type),
		}
	}

	return &record, nil
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

	valid, err := s.validateSignature(ctx, record.Data, record.Signature, common.HexToAddress(data.Grantor.Address))
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

	if data.PermissionTemplateId != "" || data.PermissionTemplateId != "0" {
		templatePermissions, err := s.getTemplatePermissions(ctx, data.PermissionTemplateId)
		if err != nil {
			return richerrors.Error{
				Code:        http.StatusUnauthorized,
				Err:         fmt.Errorf("failed to get permission template: %w", err),
				ExternalMsg: "failed to get permission template",
			}
		}
	}

	userPermGrants, cloudEvtGrants, err := autheval.UserGrantMap(&data, accessReq.Asset)
	if err != nil {
		return richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to generate user grant map: %w", err),
			ExternalMsg: "failed to generate user grant map",
		}
	}

	// TODO(lorran) merge template perms and userPermGrants

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

// TODO(lorran) move this to another package
func (s *Service) getTemplatePermissions(ctx context.Context, permissionTemplateId string) (*models.TemplateData, error) {
	templateId, ok := big.NewInt(0).SetString(permissionTemplateId, 10)
	if !ok {
		return nil, fmt.Errorf("could not convert tempalte ID string to big.Int")
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
	// TODO(lorran) check if Template JSON is in memory, if not, fetch from IPFS

	return nil, nil
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

func (s *Service) validateSignature(ctx context.Context, payload json.RawMessage, signature string, ethAddr common.Address) (bool, error) {
	if signature == "" {
		return false, errors.New("empty signature")
	}
	hexSignature := common.FromHex(signature)

	hashWithPrfx := accounts.TextHash(payload)
	err := validEOASignature(hashWithPrfx, hexSignature, ethAddr)
	if err == nil {
		return true, nil
	}
	errs := fmt.Errorf("failed to recover signer: %w", err)

	opts := &bind.CallOpts{
		Context: ctx,
	}
	contract, err := s.erc1271Mgr.NewErc1271(ethAddr, s.ethClient)
	if err != nil {
		return false, fmt.Errorf("failed to connect to address: %s: %w", ethAddr.Hex(), err)
	}

	result, err := contract.IsValidSignature(opts, common.BytesToHash(hashWithPrfx), hexSignature)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("erc1271 call failed: %w", err))
		return false, errs
	}
	return result == erc1271magicValue, nil
}

// validEOASignature validates a signature using the ECDSA recovery method.
func validEOASignature(hashWithPrfx []byte, signature []byte, ethAddr common.Address) error {
	if len(signature) != 65 {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	sigCopy[64] -= 27
	if sigCopy[64] != 0 && sigCopy[64] != 1 {
		return fmt.Errorf("invalid v byte: %d; accepted values 27 or 28", signature[64])
	}
	recoveredPubKey, err := crypto.SigToPub(hashWithPrfx, sigCopy)
	if err != nil {
		return fmt.Errorf("failed to determine public key from signature: %w", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)
	fmt.Println("recoveredAddr", recoveredAddr.Hex())
	fmt.Println("ethAddr", ethAddr.Hex())
	if recoveredAddr != ethAddr {
		return fmt.Errorf("invalid signature: %s", recoveredAddr.Hex())
	}
	return nil
}

func missingPermissionsError[T any](ethAddr common.Address, asset cloudevent.ERC721DID, lack []T) richerrors.Error {
	return richerrors.Error{
		Code:        http.StatusForbidden,
		ExternalMsg: fmt.Sprintf("Address %s lacks permissions %v for asset %s.", ethAddr.Hex(), lack, asset.String()),
	}
}
