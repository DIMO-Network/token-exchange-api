package httpcontroller

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"strconv"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/autheval"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
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
	Events []autheval.EventFilter `json:"events"`
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

	if !common.IsHexAddress(tokenReq.NFTContractAddress) {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid NFT contract address %q.", tokenReq.NFTContractAddress))
	}

	if len(tokenReq.Privileges) == 0 && len(tokenReq.CloudEvents.Events) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide at least one privilege or cloudevent")
	}

	addDefaultIdentifer(tokenReq)

	ethAddr, err := api.GetUserEthAddr(c)
	if err != nil {
		return err
	}

	accessReq, err := tokenReqToAccessReq(tokenReq, t.chainID)
	if err != nil {
		return err
	}

	err = t.accessService.ValidateAccess(c.Context(), accessReq, ethAddr)
	if err != nil {
		return fmt.Errorf("failed to validate access: %w", err)
	}

	return t.createAndReturnToken(c, tokenReq)
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
				Tags:      ce.Tags,
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

func tokenReqToAccessReq(tokenReq *TokenRequest, chainID uint64) (*access.NFTAccessRequest, error) {
	permNames := make([]string, len(tokenReq.Privileges))
	unknownPrivs := make([]int64, 0)
	for i, privID := range tokenReq.Privileges {
		permName, exists := access.PrivilegeIDToName[privID]
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

	return &access.NFTAccessRequest{
		Asset: cloudevent.ERC721DID{
			ChainID:         chainID,
			ContractAddress: common.HexToAddress(tokenReq.NFTContractAddress),
			TokenID:         big.NewInt(tokenReq.TokenID),
		},
		Permissions:  permNames,
		EventFilters: tokenReq.CloudEvents.Events,
	}, nil
}

// if any cloud event identifiers are missing assume they want everything.
func addDefaultIdentifer(tokenReq *TokenRequest) {
	for _, ce := range tokenReq.CloudEvents.Events {
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
