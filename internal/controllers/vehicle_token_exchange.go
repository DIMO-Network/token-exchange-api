package controllers

import (
	"fmt"
	"math/big"

	"github.com/DIMO-Network/token-exchange-service/internal/config"
	"github.com/DIMO-Network/token-exchange-service/internal/contracts"
	"github.com/DIMO-Network/token-exchange-service/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

type VehicleTokenExchangeController struct {
	logger           *zerolog.Logger
	contractsManager *contracts.ContractsManager
	settings         *config.Settings
	dexService       services.DexService
}

type VehiclePermissionRequest struct {
	UserAddress    string     `json:"userAddress"` //blockchain address associated with user TODO - remove and infer
	VehicleTokenID *big.Int   `json:"vehicleTokenId"`
	Privileges     []*big.Int `json:"privileges"`
}

type VehiclePermissionResponse struct {
	Token string `json:"token"`
}

func NewVehicleTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService) *VehicleTokenExchangeController {
	client, err := ethclient.Dial(settings.BlockchainNodeUrl)
	if err != nil {
		logger.Fatal().Err(err).Str("blockchainUrl", settings.BlockchainNodeUrl).Msg("Failed to dial blockchain node.")
	}
	cadr := contracts.ContractsAddressBook{
		MultiPrivilegeAddress: settings.VehicleNFTAddress,
	}
	ctmr, err := contracts.NewContractsManager(cadr, client)
	if err != nil {
		logger.Fatal().Err(err).Str("Contracts", settings.VehicleNFTAddress).Msg("Unable to initialize vehicle nft contract")
	}

	return &VehicleTokenExchangeController{
		logger:           logger,
		contractsManager: ctmr,
		settings:         settings,
		dexService:       dexService,
	}
}

func (v *VehicleTokenExchangeController) GetVehicleCommandPermissionWithScope(c *fiber.Ctx) error {
	vpr := &VehiclePermissionRequest{}
	if err := c.BodyParser(vpr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if len(vpr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide the privileges you need permission for.")
	}

	m := v.contractsManager.MultiPrivilege

	for _, p := range vpr.Privileges {
		res, err := m.HasPrivilege(nil, vpr.VehicleTokenID, p, common.HexToAddress(vpr.UserAddress))
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

	tk, err := v.dexService.SignVehiclePrivilegePayload(c.Context(), services.VehiclePrivilegeDTO{
		UserID:         vpr.UserAddress,
		VehicleTokenID: vpr.VehicleTokenID.String(),
		PrivilegeIDs:   privileges,
	})

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(VehiclePermissionResponse{
		Token: tk,
	})
}
