package controllers

import (
	"math/big"

	"github.com/DIMO-Network/token-exchange-service/internal/api"
	"github.com/DIMO-Network/token-exchange-service/internal/config"
	"github.com/DIMO-Network/token-exchange-service/internal/contracts"
	"github.com/DIMO-Network/token-exchange-service/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func NewVehicleTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dxS services.DexService) *VehicleTokenExchangeController {
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
		dexService:       dxS,
	}
}

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

func (v *VehicleTokenExchangeController) GetVehicleCommandPermissionWithScope(c *fiber.Ctx) error {
	vpr := &VehiclePermissionRequest{}
	if err := c.BodyParser(vpr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	if len(vpr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Please provide the privileges you need permission for.")
	}

	m := v.contractsManager.MultiPrivilege

	hasPrivilege := true
	token := ""
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

	var p []int64
	for _, v := range vpr.Privileges {
		p = append(p, v.Int64())
	}

	if hasPrivilege {
		tk, err := v.dexService.SignVehiclePrivilegePayload(c.Context(), services.VehiclePrivilegeDTO{
			UserID:         vpr.UserAddress,
			VehicleTokenID: vpr.VehicleTokenID.String(),
			PrivilegeIDs:   p,
		})

		if err != nil {
			return api.ErrorResponseHandler(c, err, fiber.StatusInternalServerError)
		}

		token = tk
	}

	resp := c

	if !hasPrivilege {
		resp = resp.Status(401)
	}

	return resp.JSON(fiber.Map{
		"token": token,
	})
}
