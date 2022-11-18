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
		log.Fatal(err)
	}
	cadr := contracts.ContractsAddressBook{
		MultiPriviledgeAddress: settings.MpContractAddress,
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
	UserAddress    string  `json:"userAddress"` //blockchain address associated with user TODO - remove and infer
	VehicleTokenID int64   `json:"vehicleTokenId"`
	Priviledges    []int64 `json:"priviledges"`
}

func (v VehicleTokenExchangeController) GetVehicleCommandPermissionWithScope(c *fiber.Ctx) error {
	vpr := &VehiclePermissionRequest{}
	if err := c.BodyParser(vpr); err != nil {
		return api.ErrorResponseHandler(c, err, fiber.StatusBadRequest)
	}

	m := v.contractsManager.MultiPriviledge

	hasPriviledge := true
	for _, p := range vpr.Priviledges {
		res, err := m.HasPrivilege(nil, big.NewInt(vpr.VehicleTokenID), big.NewInt(p), common.HexToAddress(vpr.UserAddress))
		if err != nil {
			return api.ErrorResponseHandler(c, err, fiber.StatusBadRequest)
		}

		if !res {
			hasPriviledge = false
			break
		}
	}

	return c.JSON(fiber.Map{
		"hasPriviledge": hasPriviledge,
	})
}
