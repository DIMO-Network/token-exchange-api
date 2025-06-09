package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

type IPFSService interface {
	Fetch(ctx context.Context, cid string) ([]byte, error)
}

var defaultAudience = []string{"dimo.zone"}

// privilege prefix to denote the 1:1 mapping to bit values and to make them easier to deprecate if desired in the future
var PermissionMap = map[int]string{
	1: "privilege:GetNonLocationHistory",  // All-time non-location data
	2: "privilege:ExecuteCommands",        // Commands
	3: "privilege:GetCurrentLocation",     // Current location
	4: "privilege:GetLocationHistory",     // All-time location
	5: "privilege:GetVINCredential",       // View VIN credential
	6: "privilege:GetLiveData",            // Subscribe live data
	7: "privilege:GetRawData",             // Raw data
	8: "privilege:GetApproximateLocation", // Approximate location
}

type TokenExchangeController struct {
	logger      *zerolog.Logger
	settings    *config.Settings
	dexService  services.DexService
	ctmr        contracts.Manager
	ethClient   bind.ContractBackend
	ipfsService IPFSService
}

type TokenRequest struct {
	// TokenID is the NFT token id.
	TokenID int64 `json:"tokenId" example:"7" validate:"required"`
	// Privileges is a list of the desired privileges. It must not be empty.
	Privileges []int64 `json:"privileges" example:"1,2,3,4" validate:"required"`
	// NFTContractAddress is the address of the NFT contract. Privileges will be checked
	// on-chain at this address. Address must be in the 0x format e.g. 0x5FbDB2315678afecb367f032d93F642f64180aa3.
	// Varying case is okay.
	NFTContractAddress string `json:"nftContractAddress" example:"0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF" validate:"required"`
	// Audience is the intended audience for the token.
	Audience []string `json:"audience" validate:"optional"`
	// CloudEvents contains requests for access to CloudEvents attached to the specified NFT.
	CloudEvents CloudEvents `json:"cloudEvents"`
}

type CloudEvents struct {
	// Events is a list of CloudEvent access requests.
	Events []EventFilter `json:"events"`
}

type EventFilter struct {
	// EventType specifies the CloudEvent type field of the documents the client wants to access.
	// It must be specified.
	EventType string `json:"eventType" validate:"required"`
	// Source specifies the CloudEvent source field for the documents the client wants to access.
	// One may also use the special value "*" for this field to select all sources.
	Source string `json:"source" validate:"required"`
	// IDs is a list of ids for the CloudEvents that the client wants to access. This list must
	// contain at least one element. If the list contains the special value "*" then the request
	// has no restrictions on id.
	IDs []string `json:"ids" validate:"required"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

func NewTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService, ipfsService IPFSService,
	contractsMgr contracts.Manager, ethClient bind.ContractBackend) (*TokenExchangeController, error) {
	return &TokenExchangeController{
		logger:      logger,
		settings:    settings,
		dexService:  dexService,
		ctmr:        contractsMgr,
		ethClient:   ethClient,
		ipfsService: ipfsService,
	}, nil
}

// ExchangeToken godoc
// @Description Returns a signed token with the requested privileges.
// @Summary     The authenticated user must have a confirmed Ethereum address with those
// @Summary     privileges on the correct token.
// @Accept      json
// @Param       tokenRequest body controllers.TokenRequest true "Requested privileges: must include address, token id, and privilege ids"
// @Produce     json
// @Success     200 {object} controllers.TokenResponse
// @Security    BearerAuth
// @Router      /tokens/exchange [post]
func (t *TokenExchangeController) ExchangeToken(c *fiber.Ctx) error {
	tokenReq := &TokenRequest{}
	if err := c.BodyParser(tokenReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if !common.IsHexAddress(tokenReq.NFTContractAddress) {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid NFT contract address %q.", tokenReq.NFTContractAddress))
	}

	nftAddr := common.HexToAddress(tokenReq.NFTContractAddress)

	t.logger.Debug().Interface("request", tokenReq).Msg("Got request.")

	if len(tokenReq.Privileges) == 0 && len(tokenReq.CloudEvents.Events) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide at least one privilege or cloudevent")
	}

	ethAddr, err := api.GetUserEthAddr(c)
	if err != nil {
		return err
	}

	// TODO(elffjs): Still silly to create this every time.
	s, err := t.ctmr.GetSacd(t.settings.ContractAddressSacd, t.ethClient)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	resPermRecord, err := s.CurrentPermissionRecord(nil, nftAddr, big.NewInt(tokenReq.TokenID), ethAddr)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Failed to get permission record: %s", err))
	}

	record, err := t.getValidSacdDoc(c.Context(), resPermRecord.Source)
	if err != nil {
		if len(tokenReq.CloudEvents.Events) != 0 {
			return fiber.NewError(fiber.StatusBadRequest, "failed to get valid sacd document, cannot evaluate claims")
		}
		// TODO(elffjs): This is in debug for now because all prod grants are in an old format.
		t.logger.Debug().Err(err).Msg("Failed to get valid SACD document")
		// If the user doesn't have a valid IPFS doc, check bitstring
		// We call the contract again because this handles the case where the caller is the owner of the asset.
		return t.evaluatePermissionsBits(c, s, nftAddr, tokenReq, ethAddr)
	}

	return t.evaluateSacdDoc(c, record, tokenReq, ethAddr)
}

// Helper function to create and return the token
func (t *TokenExchangeController) createAndReturnToken(c *fiber.Ctx, tokenReq *TokenRequest) error {
	aud := tokenReq.Audience
	if len(aud) == 0 {
		aud = defaultAudience
	}

	respSub, err := middleware.GetResponseSubject(c)
	if err != nil {
		return err
	}

	privTokenDTO := services.PrivilegeTokenDTO{
		TokenID:            strconv.FormatInt(tokenReq.TokenID, 10),
		PrivilegeIDs:       tokenReq.Privileges,
		NFTContractAddress: tokenReq.NFTContractAddress,
		Audience:           aud,
		ResponseSubject:    respSub,
	}

	if len(tokenReq.CloudEvents.Events) != 0 {
		var ces tokenclaims.CloudEvents
		for _, ce := range tokenReq.CloudEvents.Events {
			ces.Events = append(ces.Events, tokenclaims.Event{
				EventType: ce.EventType,
				Source:    ce.Source,
				IDs:       ce.IDs,
			})
		}
		privTokenDTO.CloudEvents = &ces
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), privTokenDTO)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Failed to sign privilege payload: %s", err))
	}

	return c.JSON(TokenResponse{
		Token: tk,
	})
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
//   - *PermissionRecord: A pointer to the parsed permission record if valid, or nil if the document
//     could not be fetched, parsed, or doesn't have the correct type
func (t *TokenExchangeController) getValidSacdDoc(ctx context.Context, source string) (*models.PermissionRecord, error) {
	sacdDoc, err := t.ipfsService.Fetch(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JSON from IPFS: %w", err)
	}

	var record models.PermissionRecord
	if err := json.Unmarshal(sacdDoc, &record); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}

	if record.Type != "dimo.sacd" {
		return nil, fmt.Errorf("invalid type: expected 'dimo.sacd', got '%s'", record.Type)
	}

	return &record, nil
}

// evaluateSacdDoc validates a SACD to determine if the requesting user has all the requested privileges.
// It checks the validity period of the document, verifies the grantee address matches the requester,
// and confirms all requested privileges are granted in the document.
//
// Parameters:
//   - c: The Fiber context for the HTTP request
//   - record: The SACD permission record containing the granted permissions and validity period
//   - tokenReq: The permission token request containing the requested privileges and token information
//   - grantee: The Ethereum address of the user requesting permissions
//
// Returns:
//   - error: An error if the document is invalid, expired, or missing requested permissions;
//     nil if all permissions are valid and the token is successfully created and returned
func (t *TokenExchangeController) evaluateSacdDoc(c *fiber.Ctx, record *models.PermissionRecord, tokenReq *TokenRequest, grantee common.Address) error {
	now := time.Now()
	logger := t.logger.With().Str("grantee", grantee.Hex()).Logger()
	if now.Before(record.Data.EffectiveAt) || now.After(record.Data.ExpiresAt) {
		return fiber.NewError(fiber.StatusBadRequest, "Permission record is expired or not yet effective")
	}

	if record.Data.Grantee.Address != grantee.Hex() {
		return fiber.NewError(fiber.StatusBadRequest, "Grantee address in permission record doesn't match requester")
	}

	userPermGrants, cloudEvtGrants, err := userGrantMap(record, tokenReq.NFTContractAddress, tokenReq.TokenID)
	if err != nil {
		logger.Err(err).Msg("failed to generate user grant map")
		return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
	}

	if err := evaluateCloudEvents(cloudEvtGrants, tokenReq); err != nil {
		logger.Err(err).Msg("failed to validate cloudevents agreement")
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	if err := evaluatePermissions(userPermGrants, tokenReq); err != nil {
		logger.Err(err).Msg("failed to evaluate permissions agreement")
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	// If we get here, all permission and attestation claims are valid
	return t.createAndReturnToken(c, tokenReq)
}

func evaluatePermissions(userPermissions map[string]bool, tokenReq *TokenRequest) error {
	// Check if all requested privileges are present in the permissions
	var missingPermissions []int64

	for _, privID := range tokenReq.Privileges {
		// Look up the permission name for this privilege ID
		permName, exists := PermissionMap[int(privID)]
		if !exists {
			// If we don't have a mapping for this privilege ID, consider it missing
			missingPermissions = append(missingPermissions, privID)
			continue
		}

		// Check if the user has this permission
		if !userPermissions[permName] {
			missingPermissions = append(missingPermissions, privID)
		}
	}

	// If any permissions are missing, return an error
	if len(missingPermissions) > 0 {
		return fmt.Errorf("missing permissions: %v on token id %d for asset %s", missingPermissions, tokenReq.TokenID, tokenReq.NFTContractAddress)
	}

	// If we get here, all permissions are valid
	return nil
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
func (t *TokenExchangeController) evaluatePermissionsBits(
	c *fiber.Ctx,
	s contracts.Sacd,
	nftAddr common.Address,
	tokenReq *TokenRequest,
	ethAddr common.Address,
) error {
	// Convert pr.Privileges to 2-bit array format
	mask, err := intArrayTo2BitArray(tokenReq.Privileges, 128) // Assuming max privilege is 128
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Failed to convert privileges to 2-bit array: %s", err))
	}

	ret, err := s.GetPermissions(nil, nftAddr, big.NewInt(tokenReq.TokenID), ethAddr, mask)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Failed to get permissions: %s", err))
	}

	// Collecting these because in the future we'd like to list all of them.
	var lack []int64

	for _, p := range tokenReq.Privileges {
		if ret.Bit(2*int(p)) != 1 || ret.Bit(2*int(p)+1) != 1 {
			lack = append(lack, p)
		}
	}

	if len(lack) != 0 {
		// Fall back to checking old-style privileges.
		// TODO(elffjs): If the whitelist is going to stick around, then we can probably pre-construct these.
		m, err := t.ctmr.GetMultiPrivilege(nftAddr.Hex(), t.ethClient)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
		}

		for _, p := range tokenReq.Privileges {
			hasPriv, err := m.HasPrivilege(nil, big.NewInt(tokenReq.TokenID), big.NewInt(p), ethAddr)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Failed to check privilege: %s", err))
			}

			if !hasPriv {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Address %s lacks permission %d on token id %d for asset %s.", ethAddr.Hex(), p, tokenReq.TokenID, nftAddr))
			}
		}

		t.logger.Warn().Msgf("Still using privileges %v for %s_%d", tokenReq.Privileges, nftAddr.Hex(), tokenReq.TokenID)
	}

	return t.createAndReturnToken(c, tokenReq)
}
