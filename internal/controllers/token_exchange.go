package controllers

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"strconv"

	"github.com/DIMO-Network/token-exchange-api/internal/contracts/multiprivilege"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

var defaultAudience = []string{"dimo.zone"}

type TokenExchangeController struct {
	logger       *zerolog.Logger
	dexService   services.DexService
	usersService services.UsersService
	whitelist    []common.Address
	pc           *PrivilegeChecker
}

type PermissionTokenRequest struct {
	// TokenID is the NFT token id.
	TokenID int64 `json:"tokenId" example:"7" validate:"required"`
	// Privileges is a list of the desired privileges. It must not be empty.
	Privileges []int64 `json:"privileges" example:"1,2,3,4" validate:"required"`
	// NFTContractAddress is the address of the NFT contract. Privileges will be checked
	// on-chain at this address. Address must be in the 0x format e.g. 0x5FbDB2315678afecb367f032d93F642f64180aa3.
	// Varying case is okay.
	NFTContractAddress common.Address `json:"nftContractAddress" example:"0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF" validate:"required"`
	// Audience is the intended audience for the token.
	Audience []string `json:"audience" validate:"optional"`
}

type PermissionTokenResponse struct {
	Token string `json:"token"`
}

func NewTokenExchangeController(logger *zerolog.Logger, dexService services.DexService, usersService services.UsersService, whitelist []common.Address) *TokenExchangeController {
	return &TokenExchangeController{
		logger:       logger,
		dexService:   dexService,
		usersService: usersService,
		whitelist:    whitelist,
	}
}

type PrivilegeChecker struct {
	client *ethclient.Client
}

func (c *PrivilegeChecker) CheckPermissions(
	ctx context.Context,
	nftAddr common.Address,
	tokenID int64,
	privileges []int64,
	userAddr common.Address,
) (bool, int64, error) {
	mp, err := multiprivilege.NewMultiprivilege(nftAddr, c.client)
	if err != nil {
		return false, 0, fmt.Errorf("failed to bind contract: %w", err)
	}

	for _, p := range privileges {
		res, err := mp.HasPrivilege(nil, big.NewInt(tokenID), big.NewInt(p), userAddr)
		if err != nil {
			return false, 0, fmt.Errorf("failed to call HasPrivilege: %w", err)
		}

		if !res {
			return false, p, nil
		}
	}

	return true, 0, nil
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
	var pr PermissionTokenRequest
	if err := c.BodyParser(&pr); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
	}

	t.logger.Debug().Interface("request", pr).Msg("Got request.")

	if len(pr.Privileges) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "Empty permission list.")
	}

	if !slices.Contains(t.whitelist, pr.NFTContractAddress) {
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Contract %s not whitelisted.", pr.NFTContractAddress))
	}

	userAddr := c.Locals("ethereumAddress").(common.Address)

	// TODO(elffjs): Import middleware from elsewhere.
	// ethAddr := api.GetUserEthAddr(c)
	// if ethAddr == nil {
	// 	// If eth addr not in JWT, use userID to fetch user
	// 	userID := api.GetUserID(c)
	// 	user, err := t.usersService.GetUserByID(c.Context(), userID)
	// 	if err != nil {
	// 		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user by ID")
	// 	}
	// 	if user.EthereumAddress == nil {
	// 		return fiber.NewError(fiber.StatusInternalServerError, "User Ethereum address is not set")
	// 	}
	// 	e := common.HexToAddress(*user.EthereumAddress)
	// 	ethAddr = &e
	// }

	checkOK, missing, err := t.pc.CheckPermissions(c.Context(), pr.NFTContractAddress, pr.TokenID, pr.Privileges, userAddr)
	if err != nil {
		return err
	} else if !checkOK {
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Missing privilege %d.", missing))
	}

	aud := pr.Audience
	if len(aud) == 0 {
		aud = defaultAudience
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), services.PrivilegeTokenDTO{
		TokenID:            strconv.FormatInt(pr.TokenID, 10),
		PrivilegeIDs:       pr.Privileges,
		NFTContractAddress: pr.NFTContractAddress,
		Audience:           aud,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error signing token.")
	}

	return c.JSON(PermissionTokenResponse{
		Token: tk,
	})
}
