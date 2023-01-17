package controllers

import (
	"fmt"
	"math/big"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/common"
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
	TokenID            *big.Int   `json:"tokenId" validate:"required"`
	Privileges         []*big.Int `json:"privileges"`
	NFTContractAddress string     `json:"nftContractAddress"`
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

func (t *TokenExchangeController) GetDeviceCommandPermissionWithScope(c *fiber.Ctx) error {
	pr := &PermissionTokenRequest{}
	if err := c.BodyParser(pr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if len(pr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide the privileges you need permission for.")
	}

	if common.IsHexAddress(pr.NFTContractAddress) {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide NFT contract address you need permission for.")
	}

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

	claims := services.GetJWTTokenClaims(c)
	userID := claims["sub"].(string)
	user, err := t.usersService.GetUserByID(c.Context(), userID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			t.logger.Debug().Str("userId", userID).Msg("User not found.")
			return fiber.NewError(fiber.StatusForbidden, "User not found!")
		}
		t.logger.Error().Str("userID", userID).Msg("Users api unavailable!")
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	userEthAddress := user.GetEthereumAddress()
	addr := common.HexToAddress(userEthAddress)
	if userEthAddress == "" {
		t.logger.Debug().Str("userID", userID).Msg("Ethereum address not found!")
		return fiber.NewError(fiber.StatusForbidden, "Wallet address not found!")
	}

	m := ctmr.MultiPrivilege

	for _, p := range pr.Privileges {
		res, err := m.HasPrivilege(nil, pr.TokenID, p, addr)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !res {
			return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Address lacks privilege %d.", p))
		}
	}

	var privileges []int64
	for _, v := range pr.Privileges {
		privileges = append(privileges, v.Int64())
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), services.PrivilegeTokenDTO{
		UserEthAddress:     userEthAddress,
		TokenID:            pr.TokenID.String(),
		PrivilegeIDs:       privileges,
		NFTContractAddress: pr.NFTContractAddress,
	})

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(PermissionTokenResponse{
		Token: tk,
	})
}
