package controllers

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

var defaultAudience = []string{"dimo.zone"}

type TokenExchangeController struct {
	logger       *zerolog.Logger
	settings     *config.Settings
	dexService   services.DexService
	usersService services.UsersService
	ctmr         contracts.Manager
	ctinit       contracts.ContractCallInitializer
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
}

type PermissionTokenResponse struct {
	Token string `json:"token"`
}

func NewTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService,
	usersService services.UsersService, contractsMgr contracts.Manager, contractsInit contracts.ContractCallInitializer) *TokenExchangeController {
	return &TokenExchangeController{
		logger:       logger,
		settings:     settings,
		dexService:   dexService,
		usersService: usersService,
		ctmr:         contractsMgr,
		ctinit:       contractsInit,
	}
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
	pr := &PermissionTokenRequest{}
	if err := c.BodyParser(pr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if !common.IsHexAddress(pr.NFTContractAddress) {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid NFT contract address %q.", pr.NFTContractAddress))
	}

	nftAddr := common.HexToAddress(pr.NFTContractAddress)

	t.logger.Debug().Interface("request", pr).Msg("Got request.")

	if len(pr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide at least one privilege.")
	}

	// Contract address has been validated in the middleware
	// TODO(elffjs): Stop constructing these every darned time.
	client, err := t.ctinit.InitContractCall(t.settings.BlockchainNodeURL)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	m, err := t.ctmr.GetMultiPrivilege(nftAddr.Hex(), client)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	s, err := t.ctmr.GetSacd(t.settings.ContractAddressSacd, client)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	ethAddr := api.GetUserEthAddr(c)
	if ethAddr == nil {
		// If eth addr not in JWT, use userID to fetch user
		userID := api.GetUserID(c)
		user, err := t.usersService.GetUserByID(c.Context(), userID)
		if err != nil {
			// TODO(elffjs): If there's no record here, it's a client error.
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user by ID")
		}
		if user.EthereumAddress == nil || !common.IsHexAddress(*user.EthereumAddress) {
			return fiber.NewError(fiber.StatusBadRequest, "No Ethereum address in JWT or on record.")
		}
		e := common.HexToAddress(*user.EthereumAddress)
		ethAddr = &e
	}

	for _, p := range pr.Privileges {
		if p < 0 || p >= 128 {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid permission id %d. These must be non-negative and less than 128.", p))
		}

		resMulti, err := m.HasPrivilege(nil, big.NewInt(pr.TokenID), big.NewInt(p), *ethAddr)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if resMulti {
			continue
		}

		// TODO(elffjs): Get this down to one call.
		resSacd, err := s.HasPermission(nil, nftAddr, big.NewInt(pr.TokenID), *ethAddr, uint8(p))
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !resSacd {
			return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Address %s lacks permission %d on token id %d for asset %s.", *ethAddr, p, pr.TokenID, nftAddr))
		}
	}

	aud := pr.Audience
	if len(aud) == 0 {
		aud = defaultAudience
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), services.PrivilegeTokenDTO{
		UserEthAddress:     ethAddr.Hex(),
		TokenID:            strconv.FormatInt(pr.TokenID, 10),
		PrivilegeIDs:       pr.Privileges,
		NFTContractAddress: nftAddr.Hex(),
		Audience:           aud,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(PermissionTokenResponse{
		Token: tk,
	})
}
