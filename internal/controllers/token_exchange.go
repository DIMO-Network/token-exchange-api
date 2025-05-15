package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
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

type PermissionTokenRequest struct {
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
	// CloudEvent request, includes attestations
	CloudEvents *tokenclaims.CloudEvents `json:"cloudEvents"`
}

type PermissionTokenResponse struct {
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

// GetDeviceCommandPermissionWithScope godoc
// @Description Returns a signed token with the requested privileges.
// @Summary     The authenticated user must have a confirmed Ethereum address with those
// @Summary     privileges on the correct token.
// @Accept      json
// @Param       tokenRequest body controllers.PermissionTokenRequest true "Requested privileges: must include address, token id, and privilege ids"
// @Produce     json
// @Success     200 {object} controllers.PermissionTokenResponse
// @Security    BearerAuth
// @Router      /tokens/exchange [post]
func (t *TokenExchangeController) GetDeviceCommandPermissionWithScope(c *fiber.Ctx) error {
	tokenReq := &PermissionTokenRequest{}
	if err := c.BodyParser(tokenReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if !common.IsHexAddress(tokenReq.NFTContractAddress) {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid NFT contract address %q.", tokenReq.NFTContractAddress))
	}

	nftAddr := common.HexToAddress(tokenReq.NFTContractAddress)

	t.logger.Debug().Interface("request", tokenReq).Msg("Got request.")

	if len(tokenReq.Privileges) == 0 && tokenReq.CloudEvents == nil {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide at least one privilege or cloudevent")
	}

	ethAddr := api.GetUserEthAddr(c)
	if ethAddr == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Ethereum address required in JWT.")
	}

	// TODO(elffjs): Still silly to create this every time.
	s, err := t.ctmr.GetSacd(t.settings.ContractAddressSacd, t.ethClient)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	resPermRecord, err := s.CurrentPermissionRecord(nil, nftAddr, big.NewInt(tokenReq.TokenID), *ethAddr)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	record, err := t.getValidSacdDoc(c.Context(), resPermRecord.Source)
	if err != nil {
		t.logger.Warn().Err(err).Msg("Failed to get valid SACD document")
		if tokenReq.CloudEvents != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to get valid sacd document, cannot evaluate claims")
		}
		// If the user doesn't have a valid IPFS doc, check bitstring
		return t.evaluatePermissionsBits(c, s, nftAddr, tokenReq, ethAddr)
	}

	return t.evaluateSacdDoc(c, record, tokenReq, ethAddr)
}

// Helper function to create and return the token
func (t *TokenExchangeController) createAndReturnToken(c *fiber.Ctx, pr *PermissionTokenRequest, ethAddr *common.Address) error {
	aud := pr.Audience
	if len(aud) == 0 {
		aud = defaultAudience
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), services.PrivilegeTokenDTO{
		UserEthAddress:     ethAddr.Hex(),
		TokenID:            strconv.FormatInt(pr.TokenID, 10),
		PrivilegeIDs:       pr.Privileges,
		CloudEvents:        pr.CloudEvents,
		NFTContractAddress: pr.NFTContractAddress,
		Audience:           aud,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(PermissionTokenResponse{
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
//   - pr: The permission token request containing the requested privileges and token information
//   - grantee: The Ethereum address of the user requesting permissions
//
// Returns:
//   - error: An error if the document is invalid, expired, or missing requested permissions;
//     nil if all permissions are valid and the token is successfully created and returned
func (t *TokenExchangeController) evaluateSacdDoc(c *fiber.Ctx, record *models.PermissionRecord, tokenReq *PermissionTokenRequest, grantee *common.Address) error {
	now := time.Now()
	logger := t.logger.With().Str("grantee", grantee.Hex()).Logger()
	if now.Before(record.Data.EffectiveAt) || now.After(record.Data.ExpiresAt) {
		return fiber.NewError(fiber.StatusBadRequest, "Permission record is expired or not yet effective")
	}

	if record.Data.Grantee.Address != grantee.Hex() {
		return fiber.NewError(fiber.StatusBadRequest, "Grantee address in permission record doesn't match requester")
	}

	userPermGrants, cloudEvtGrants := t.userGrantMap(record)
	for _, agg := range record.Data.Agreements {
		switch agg.Type {
		case "cloudevent":
			if agg.EffectiveAt != nil && !agg.EffectiveAt.IsZero() {
				if time.Now().Before(*agg.EffectiveAt) {
					logger.Info().Msgf("agreement not yet in effect: %s", agg.EffectiveAt.String())
					return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
				}
			}

			if agg.ExpiresAt != nil && !agg.ExpiresAt.IsZero() {
				if agg.ExpiresAt.Before(time.Now()) {
					logger.Info().Msgf("agreement expired: %s", agg.ExpiresAt.String())
					return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
				}
			}

			if valid, err := t.validateAssetDID(record.Data.Asset, tokenReq); err != nil || !valid {
				logger.Err(err).Msgf("failed to validate attestation asset: %s", record.Data.Asset)
				return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
			}

			if err := t.evaluateCloudEvents(cloudEvtGrants, tokenReq); err != nil {
				logger.Err(err).Msg("failed to validate request")
				return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
			}

		case "permissions":
			// Validate the asset DID if it exists in the record
			valid, err := t.validateAssetDID(agg.Asset, tokenReq)
			if err != nil || !valid {
				logger.Err(err).Msgf("failed to validate asset did %s in permission agreement", agg.Asset)
				return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
			}

			if err := t.evaluatePermissions(userPermGrants, tokenReq); err != nil {
				logger.Err(err).Msg("failed to evaluate permissions agreement")
				return fiber.NewError(fiber.StatusBadRequest, "failed to validate request")
			}
		}
	}

	// If we get here, all permission and attestation claims are valid
	return t.createAndReturnToken(c, tokenReq, grantee)
}

func (t *TokenExchangeController) userGrantMap(record *models.PermissionRecord) (map[string]bool, map[string]map[string]*shared.StringSet) {
	userPermGrants := make(map[string]bool)
	cloudEvtGrants := make(map[string]map[string]*shared.StringSet)

	// Aggregates all the permission and attestation grants the user has.
	for _, agreement := range record.Data.Agreements {
		switch agreement.Type {
		case "cloudevent":
			if _, ok := cloudEvtGrants[agreement.EventType]; !ok {
				cloudEvtGrants[agreement.EventType] = map[string]*shared.StringSet{}
			}

			source := agreement.Source
			if agreement.Source == nil {
				source = &tokenclaims.GlobalAttestationPermission
			}

			if _, ok := cloudEvtGrants[agreement.EventType][*source]; !ok {
				cloudEvtGrants[agreement.EventType][*source] = shared.NewStringSet()
			}

			for _, id := range agreement.ID {
				cloudEvtGrants[agreement.EventType][*source].Add(id)
			}

		case "permissions":
			// Add permissions from this agreement
			for _, permission := range agreement.Permissions {
				userPermGrants[permission.Name] = true
			}
		}
	}

	return userPermGrants, cloudEvtGrants

}

func (t *TokenExchangeController) evaluatePermissions(userPermissions map[string]bool, tokenReq *PermissionTokenRequest) error {
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

	return nil
}

func (t *TokenExchangeController) evaluateCloudEvents(agreement map[string]map[string]*shared.StringSet, tokenReq *PermissionTokenRequest) error {
	var err error
	for _, req := range tokenReq.CloudEvents.Events {
		grantedAggs, ok := agreement[req.EventType]
		if !ok {
			err = errors.Join(err, fmt.Errorf("lacking grant for requested event type: %s", req.EventType))
			continue
		}

		source := req.Source
		if source == nil {
			source = &tokenclaims.GlobalAttestationPermission
		}

		if _, ok := grantedAggs[*source]; !ok {
			err = errors.Join(err, fmt.Errorf("lacking %s grant for requested source: %s", req.EventType, *source))
			continue
		}

		// NOTE: do we want to explicitly enforce that
		// someone has to ask for the exact ids they've been granted?
		if len(grantedAggs[*source].Slice()) == 0 {
			continue
		}

		if len(req.IDs) == 0 {
			err = errors.Join(err, fmt.Errorf("requesting global access to %s cloudevents for %s but only granted subset", *source, req.EventType))
		}

		for _, reqID := range req.IDs {
			if !grantedAggs[*source].Contains(reqID) {
				err = errors.Join(err, fmt.Errorf("lacking grant from %s for %s cloudevent id: %s", *source, req.EventType, reqID))
			}
		}
	}

	return err
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
//   - pr: The permission token request containing token ID and requested privileges
//   - ethAddr: The Ethereum address of the user requesting permissions
//
// Returns:
//   - error: An error if the user lacks any requested permissions or if there's a system error,
//     otherwise nil if the token is successfully created and returned
func (t *TokenExchangeController) evaluatePermissionsBits(
	c *fiber.Ctx,
	s contracts.Sacd,
	nftAddr common.Address,
	pr *PermissionTokenRequest,
	ethAddr *common.Address,
) error {
	// Convert pr.Privileges to 2-bit array format
	mask, err := intArrayTo2BitArray(pr.Privileges, 128) // Assuming max privilege is 128
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	ret, err := s.GetPermissions(nil, nftAddr, big.NewInt(pr.TokenID), *ethAddr, mask)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Collecting these because in the future we'd like to list all of them.
	var lack []int64

	for _, p := range pr.Privileges {
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

		for _, p := range pr.Privileges {
			hasPriv, err := m.HasPrivilege(nil, big.NewInt(pr.TokenID), big.NewInt(p), *ethAddr)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}

			if !hasPriv {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Address %s lacks permission %d on token id %d for asset %s.", ethAddr.Hex(), p, pr.TokenID, nftAddr))
			}
		}

		t.logger.Warn().Msgf("Still using privileges %v for %s_%d", pr.Privileges, nftAddr.Hex(), pr.TokenID)
	}

	return t.createAndReturnToken(c, pr, ethAddr)
}
