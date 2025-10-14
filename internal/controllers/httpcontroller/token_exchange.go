package httpcontroller

import (
	"context"
	"fmt"
	"math/big"
	"net/http"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/DIMO-Network/token-exchange-api/internal/services/access"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
)

type DexService interface {
	SignPrivilegePayload(ctx context.Context, req services.PrivilegeTokenDTO) (string, error)
}
type AccessService interface {
	ValidateAccess(ctx context.Context, req *access.NFTAccessRequest, ethAddr common.Address) error
}

var defaultAudience = []string{"dimo.zone"}

type TokenExchangeController struct {
	chainID       uint64
	dexService    DexService
	accessService AccessService
}

type TokenRequest struct {
	// Asset DID of the asset that permissions are being requested for currently either did:erc721 or did:ethr
	Asset string `json:"asset"`
	// CloudEvents contains requests for access to CloudEvents attached to the specified NFT.
	CloudEvents CloudEvents `json:"cloudEvents"`
	// Permissions is a list of the desired permissions.
	Permissions []string `json:"permissions"`
	// Audience is the intended audience for the token.
	Audience []string `json:"audience" validate:"optional"`

	// TokenID is the NFT token id.
	// If asset is provided, this is ignored.
	// Deprecated: Use Asset instead.
	TokenID int64 `json:"tokenId" example:"7"`
	// Privileges is a list of the desired privileges. It must not be empty.
	// If Permissions are provided, this is ignored.
	// Deprecated: Use Permissions instead.
	Privileges []int64 `json:"privileges" example:"1,2,3,4"`
	// NFTContractAddress is the address of the NFT contract. Privileges will be checked
	// on-chain at this address. Address must be in the 0x format e.g. 0x5FbDB2315678afecb367f032d93F642f64180aa3.
	// Varying case is okay.
	// If asset is provided, this is ignored.
	// Deprecated: Use Asset instead.
	NFTContractAddress string `json:"nftContractAddress" example:"0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"`
}
type CloudEvents struct {
	Events []models.EventFilter `json:"events"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

func NewTokenExchangeController(settings *config.Settings, dexService DexService, accessService AccessService) (*TokenExchangeController, error) {
	return &TokenExchangeController{
		chainID:       settings.DIMORegistryChainID,
		dexService:    dexService,
		accessService: accessService,
	}, nil
}

// ExchangeToken godoc
// @Description Returns a signed token with the requested privileges.
// @Summary     The authenticated user must have a confirmed Ethereum address with those
// @Summary     privileges on the correct token.
// @Accept      json
// @Param       tokenRequest body httpcontroller.TokenRequest true "Requested privileges: must include address, token id, and privilege ids"
// @Produce     json
// @Success     200 {object} httpcontroller.TokenResponse
// @Security    BearerAuth
// @Router      /tokens/exchange [post]
func (t *TokenExchangeController) ExchangeToken(c *fiber.Ctx) error {
	tokenReq := &TokenRequest{}
	if err := c.BodyParser(tokenReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}
	accessReq, err := tokenReqToAccessReq(tokenReq, t.chainID)
	if err != nil {
		return err
	}

	if len(accessReq.Permissions) == 0 && len(accessReq.EventFilters) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide at least one privilege or cloudevent")
	}

	addDefaultIdentifiers(accessReq)

	ethAddr, err := api.GetUserEthAddr(c)
	if err != nil {
		return err
	}

	err = t.accessService.ValidateAccess(c.Context(), accessReq, ethAddr)
	if err != nil {
		return fmt.Errorf("failed to validate access: %w", err)
	}

	return t.createAndReturnToken(c, tokenReq.Audience, accessReq)
}

// Helper function to create and return the token
func (t *TokenExchangeController) createAndReturnToken(c *fiber.Ctx, aud []string, accessReq *access.NFTAccessRequest) error {
	if len(aud) == 0 {
		aud = defaultAudience
	}

	respSub, err := middleware.GetResponseSubject(c)
	if err != nil {
		return err
	}

	privTokenDTO := services.PrivilegeTokenDTO{
		NFTAccessRequest: accessReq,
		Audience:         aud,
		ResponseSubject:  respSub,
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), privTokenDTO)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("Failed to sign privilege payload: %s", err))
	}

	return c.JSON(TokenResponse{
		Token: tk,
	})
}

func tokenReqToAccessReq(tokenReq *TokenRequest, chainID uint64) (*access.NFTAccessRequest, error) {
	assetDID, err := assetDIDFromTokenReq(tokenReq, chainID)
	if err != nil {
		return nil, err
	}
	if len(tokenReq.Permissions) == 0 {
		tokenReq.Permissions, err = getPermissionsFromPrivileges(tokenReq.Privileges)
		if err != nil {
			return nil, err
		}
	}
	return &access.NFTAccessRequest{
		Asset:        assetDID,
		Permissions:  tokenReq.Permissions,
		EventFilters: tokenReq.CloudEvents.Events,
	}, nil
}

// addDefaultIdentifiers update tokenReq.CloudEvents.Events so that if any cloud event identifiers are missing assume they want everything.
func addDefaultIdentifiers(tokenReq *access.NFTAccessRequest) {
	for i := range tokenReq.EventFilters {
		ce := &tokenReq.EventFilters[i]
		if ce.EventType == "" {
			ce.EventType = tokenclaims.GlobalIdentifier
		}
		if ce.Source == "" {
			ce.Source = tokenclaims.GlobalIdentifier
		}
		if len(ce.IDs) == 0 {
			ce.IDs = []string{tokenclaims.GlobalIdentifier}
		}
		if len(ce.Tags) == 0 {
			ce.Tags = []string{tokenclaims.GlobalIdentifier}
		}
	}
}

func getPermissionsFromPrivileges(privileges []int64) ([]string, error) {
	permNames := make([]string, len(privileges))
	unknownPrivs := make([]int64, 0)
	for i, privID := range privileges {
		permName, exists := tokenclaims.PrivilegeIDToName[privID]
		if !exists {
			// If we don't have a mapping for this privilege ID, consider it missing
			unknownPrivs = append(unknownPrivs, privID)
			continue
		}
		permNames[i] = permName
	}

	if len(unknownPrivs) > 0 {
		return nil, richerrors.Error{
			Code:        http.StatusBadRequest,
			Err:         fmt.Errorf("unknown privileges %v", unknownPrivs),
			ExternalMsg: fmt.Sprintf("unknown privileges %v", unknownPrivs),
		}
	}
	return permNames, nil
}

func assetDIDFromTokenReq(tokenReq *TokenRequest, chainID uint64) (cloudevent.ERC721DID, error) {
	if tokenReq.Asset != "" {
		erc721DID, err := cloudevent.DecodeERC721DID(tokenReq.Asset)
		if err == nil {
			return erc721DID, nil
		}

		ethrDID, err := cloudevent.DecodeEthrDID(tokenReq.Asset)
		if err == nil {
			// If the asset is an EthrDID, we need to convert it to an ERC721DID with a token ID of 0
			return cloudevent.ERC721DID{
				ChainID:         chainID,
				ContractAddress: ethrDID.ContractAddress,
				TokenID:         big.NewInt(0),
			}, nil
		}

		return cloudevent.ERC721DID{}, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid asset DID %q.", tokenReq.Asset))
	}
	if !common.IsHexAddress(tokenReq.NFTContractAddress) {
		return cloudevent.ERC721DID{}, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid NFT contract address %q.", tokenReq.NFTContractAddress))
	}

	return cloudevent.ERC721DID{
		ChainID:         chainID,
		ContractAddress: common.HexToAddress(tokenReq.NFTContractAddress),
		TokenID:         big.NewInt(tokenReq.TokenID),
	}, nil
}
