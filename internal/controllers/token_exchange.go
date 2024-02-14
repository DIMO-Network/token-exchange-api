package controllers

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strconv"
	"strings"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type TokenExchangeController struct {
	logger       *zerolog.Logger
	settings     *config.Settings
	dexService   services.DexService
	usersService services.UsersService
}

type PermissionTokenRequest struct {
	// TokenID is the NFT token id.
	TokenID int64 `json:"tokenId"`
	// Privileges is a list of the desired privileges. It must not be empty.
	Privileges []int64 `json:"privileges"`
	// NFTContractAddress is the address of the NFT contract. Privileges will be checked
	// on-chain at this address. Address must be in the 0x format e.g. 0x5FbDB2315678afecb367f032d93F642f64180aa3.
	// Varying case is okay.
	NFTContractAddress string `json:"nftContractAddress"`
}

type PermissionTokenResponse struct {
	Token string `json:"token"`
}

func NewTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService, usersService services.UsersService) *TokenExchangeController {
	return &TokenExchangeController{
		logger:       logger,
		settings:     settings,
		dexService:   dexService,
		usersService: usersService,
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

	pr.NFTContractAddress = strings.ToLower(pr.NFTContractAddress)

	t.logger.Info().Interface("request", pr).Msg("Got request.")

	if len(pr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide the privileges you need permission for.")
	}

	// Contract address has been validated in the middleware
	client, err := contracts.InitContractCall(t.settings.BlockchainNodeURL)
	if err != nil {
		t.logger.Fatal().Err(err).Str("blockchainUrl", t.settings.BlockchainNodeURL).Msg("Failed to dial blockchain node")
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	ctmr, err := contracts.NewContractsManager(pr.NFTContractAddress, client)
	if err != nil {
		t.logger.Fatal().Err(err).Str("Contracts", pr.NFTContractAddress).Msg("Unable to initialize nft contract")
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	ethAddr := api.GetUserEthAddr(c)
	if ethAddr == nil {
		// If eth addr not in JWT, use userID to fetch user
		userID := api.GetUserID(c)
		user, err := t.usersService.GetUserByID(c.Context(), userID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user by ID")
		}
		if user.EthereumAddress == nil {
			return fiber.NewError(fiber.StatusInternalServerError, "User Ethereum address is not set")
		}
		e := common.HexToAddress(*user.EthereumAddress)
		ethAddr = &e
	}

	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			t.logger.Debug().Str("ethAddr", ethAddr.Hex()).Msg("Ethereum address not found.")
			return fiber.NewError(fiber.StatusForbidden, "Ethereum address not found!")
		}
		t.logger.Error().Str("ethAddr", ethAddr.Hex()).Msg("Users api unavailable!")
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	m := ctmr.MultiPrivilege

	for _, p := range pr.Privileges {
		res, err := m.HasPrivilege(nil, big.NewInt(pr.TokenID), big.NewInt(p), *ethAddr)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !res {
			return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Address lacks privilege %d.", p))
		}
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), services.PrivilegeTokenDTO{
		UserEthAddress:     ethAddr.Hex(),
		TokenID:            strconv.FormatInt(pr.TokenID, 10),
		PrivilegeIDs:       pr.Privileges,
		NFTContractAddress: pr.NFTContractAddress,
	})

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(PermissionTokenResponse{
		Token: tk,
	})
}
