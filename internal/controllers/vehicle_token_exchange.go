package controllers

import (
	"log"
	"math/big"

	"github.com/DIMO-Network/token-exchange-service/internal/api"
	"github.com/DIMO-Network/token-exchange-service/internal/config"
	"github.com/DIMO-Network/token-exchange-service/internal/contracts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func NewVehicleTokenExchangeController(logger *zerolog.Logger, settings *config.Settings) *VehicleTokenExchangeController {
	client, err := ethclient.Dial(settings.BlockchainNodeUrl)
	if err != nil {
		logger.Fatal().Err(err).Str("blockchainUrl", settings.BlockchainNodeUrl).Msg("Failed to dial blockchain node.")
	}
	cadr := contracts.ContractsAddressBook{
		MultiPrivilegeAddress: settings.MpContractAddress,
	}
	ctmr, err := contracts.NewContractsManager(cadr, client)
	if err != nil {
		log.Fatal(err)
	}

	return &VehicleTokenExchangeController{
		logger:           logger,
		contractsManager: ctmr,
		settings:         settings,
	}
}

type VehicleTokenExchangeController struct {
	logger           *zerolog.Logger
	contractsManager *contracts.ContractsManager
	settings         *config.Settings
}

type VehiclePermissionRequest struct {
	UserAddress    string     `json:"userAddress"` //blockchain address associated with user TODO - remove and infer
	VehicleTokenID *big.Int   `json:"vehicleTokenId"`
	Privileges     []*big.Int `json:"privileges"`
}

func (v *VehicleTokenExchangeController) GetVehicleCommandPermissionWithScope(c *fiber.Ctx) error {
	vpr := &VehiclePermissionRequest{}
	if err := c.BodyParser(vpr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	m := v.contractsManager.MultiPrivilege

	hasPrivilege := true
	for _, p := range vpr.Privileges {
		res, err := m.HasPrivilege(nil, vpr.VehicleTokenID, p, common.HexToAddress(vpr.UserAddress))
		if err != nil {
			return api.ErrorResponseHandler(c, err, fiber.StatusInternalServerError)
		}

		if !res {
			hasPrivilege = false
			break
		}
	}

	return c.JSON(fiber.Map{
		"hasPrivilege": hasPrivilege,
	})
}
