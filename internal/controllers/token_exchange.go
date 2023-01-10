package controllers

import (
	"fmt"
	"log"
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

type DeviceTokenExchangeController struct {
	logger       *zerolog.Logger
	settings     *config.Settings
	dexService   services.DexService
	usersService services.UsersService
}

type DevicePermissionRequest struct {
	DeviceTokenID      *big.Int   `json:"deviceTokenId" validate:"required"`
	Privileges         []*big.Int `json:"privileges"`
	NFTContractAddress string     `json:"nftContractAddress"`
}

type DevicePermissionResponse struct {
	Token string `json:"token"`
}

func NewDeviceTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService, usersService services.UsersService) *DeviceTokenExchangeController {

	return &DeviceTokenExchangeController{
		logger:       logger,
		settings:     settings,
		dexService:   dexService,
		usersService: usersService,
	}
}

func (v *DeviceTokenExchangeController) GetDeviceCommandPermissionWithScope(c *fiber.Ctx) error {
	vpr := &DevicePermissionRequest{}
	if err := c.BodyParser(vpr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if len(vpr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide the privileges you need permission for.")
	}

	if vpr.NFTContractAddress == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide NFT contract address you need permission for.")
	}

	client, cadr, err := contracts.InitContractCall(v.settings.BlockchainNodeURL, vpr.NFTContractAddress)
	if err != nil {
		v.logger.Fatal().Err(err).Str("blockchainUrl", v.settings.BlockchainNodeURL).Msg("Failed to dial blockchain node")
	}

	ctmr, err := contracts.NewContractsManager(cadr, client)
	if err != nil {
		v.logger.Fatal().Err(err).Str("Contracts", vpr.NFTContractAddress).Msg("Unable to initialize nft contract")
	}

	claims := services.GetJWTTokenClaims(c)
	userID := claims["sub"].(string)
	user, err := v.usersService.GetUserByID(c.Context(), userID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			v.logger.Debug().Str("userId", userID).Msg("User not found.")
			return fiber.NewError(fiber.StatusForbidden, "User not found!")
		}
		v.logger.Error().Str("userID", userID).Msg("Users api unavailable!")
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	userEthAddress := user.GetEthereumAddress()
	addr := common.HexToAddress(userEthAddress)
	if userEthAddress == "" {
		v.logger.Debug().Str("userID", userID).Msg("Ethereum address not found!")
		return fiber.NewError(fiber.StatusForbidden, "Wallet address not found!")
	}

	m := ctmr.MultiPrivilege

	for _, p := range vpr.Privileges {
		log.Println(vpr.DeviceTokenID, p, addr)
		res, err := m.HasPrivilege(nil, vpr.DeviceTokenID, p, addr)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !res {
			return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Address lacks privilege %d.", p))
		}
	}

	var privileges []int64
	for _, v := range vpr.Privileges {
		privileges = append(privileges, v.Int64())
	}

	tk, err := v.dexService.SignPrivilegePayload(c.Context(), services.DevicePrivilegeDTO{
		UserEthAddress:     userEthAddress,
		DeviceTokenID:      vpr.DeviceTokenID.String(),
		PrivilegeIDs:       privileges,
		NFTContractAddress: vpr.NFTContractAddress,
	})

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(DevicePermissionResponse{
		Token: tk,
	})
}
