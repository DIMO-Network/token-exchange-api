package controllers

import (
	"fmt"
	"math/big"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DeviceTokenExchangeController struct {
	logger           *zerolog.Logger
	contractsManager *contracts.ContractsManager
	settings         *config.Settings
	dexService       services.DexService
	usersService     services.UsersService
}

type DevicePermissionRequest struct {
	DeviceTokenID *big.Int   `json:"deviceTokenId"`
	Privileges    []*big.Int `json:"privileges"`
}

type DevicePermissionResponse struct {
	Token string `json:"token"`
}

func NewDeviceTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService, usersService services.UsersService) *DeviceTokenExchangeController {
	client, err := ethclient.Dial(settings.BlockchainNodeURL)
	if err != nil {
		logger.Fatal().Err(err).Str("blockchainUrl", settings.BlockchainNodeURL).Msg("Failed to dial blockchain node.")
	}
	cadr := contracts.ContractsAddressBook{
		MultiPrivilegeAddress: settings.VehicleNFTAddress,
	}
	ctmr, err := contracts.NewContractsManager(cadr, client)
	if err != nil {
		logger.Fatal().Err(err).Str("Contracts", settings.VehicleNFTAddress).Msg("Unable to initialize nft contract")
	}

	return &DeviceTokenExchangeController{
		logger:           logger,
		contractsManager: ctmr,
		settings:         settings,
		dexService:       dexService,
		usersService:     usersService,
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

	m := v.contractsManager.MultiPrivilege

	for _, p := range vpr.Privileges {
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
		UserEthAddress: userEthAddress,
		DeviceTokenID:  vpr.DeviceTokenID.String(),
		PrivilegeIDs:   privileges,
	})

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(DevicePermissionResponse{
		Token: tk,
	})
}
