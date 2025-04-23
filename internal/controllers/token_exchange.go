package controllers

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

var defaultAudience = []string{"dimo.zone"}

type TokenExchangeController struct {
	logger     *zerolog.Logger
	settings   *config.Settings
	dexService services.DexService
	ctmr       contracts.Manager
	ethClient  bind.ContractBackend
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
	contractsMgr contracts.Manager, ethClient bind.ContractBackend) *TokenExchangeController {
	return &TokenExchangeController{
		logger:     logger,
		settings:   settings,
		dexService: dexService,
		ctmr:       contractsMgr,
		ethClient:  ethClient,
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

	ethAddr := api.GetUserEthAddr(c)
	if ethAddr == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Ethereum address required in JWT.")
	}

	// TODO(elffjs): Still silly to create this every time.
	s, err := t.ctmr.GetSacd(t.settings.ContractAddressSacd, t.ethClient)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	mask := big.NewInt(0)

	for _, p := range pr.Privileges {
		if p < 0 || p >= 128 {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid permission id %d. These must be non-negative and less than 128.", p))
		}

		mask.SetBit(mask, 2*int(p), 1)
		mask.SetBit(mask, 2*int(p)+1, 1)
	}

	ret, err := s.GetPermissions(nil, nftAddr, big.NewInt(pr.TokenID), *ethAddr, mask)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Collecting these because in the future we'd like to list all of them.
	var lack []int64

	for _, p := range pr.Privileges {
		if ret.Bit(2*int(p)) != 1 || ret.Bit(2*int(p)+1) != 1 {
			lack = append(lack, p)
		}
	}

	if len(lack) != 0 {
		// Fall back to checking old-style privileges.
		// TODO(elffjs): If the whitelist is going to stick around, then we can probably pre-construct these.
		m, err := t.ctmr.GetMultiPrivilege(nftAddr.Hex(), t.ethClient)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
		}

		for _, p := range pr.Privileges {
			hasPriv, err := m.HasPrivilege(nil, big.NewInt(pr.TokenID), big.NewInt(p), *ethAddr)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}

			if !hasPriv {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Address %s lacks privilege %d on token id %d for asset %s.", ethAddr.Hex(), p, pr.TokenID, nftAddr))
			}
		}

		t.logger.Warn().Msgf("Still using privileges %v for %s_%d", pr.Privileges, nftAddr.Hex(), pr.TokenID)
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
