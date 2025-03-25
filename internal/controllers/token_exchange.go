package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	logger       *zerolog.Logger
	settings     *config.Settings
	dexService   services.DexService
	usersService services.UsersService
	ctmr         contracts.Manager
	ethClient    bind.ContractBackend
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
type PermissionRecord struct {
	SpecVersion string    `json:"specversion"`
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Data        struct {
		Grantor struct {
			Address string `json:"address"`
		} `json:"grantor"`
		Grantee struct {
			Address string `json:"address"`
		} `json:"grantee"`
		EffectiveAt time.Time `json:"effectiveAt"`
		ExpiresAt   time.Time `json:"expiresAt"`
		Agreement   []struct {
			Type        string `json:"type"`
			Permissions []struct {
				Name string `json:"name"`
			} `json:"permissions"`
		} `json:"agreement"`
	} `json:"data"`
}

func NewTokenExchangeController(logger *zerolog.Logger, settings *config.Settings, dexService services.DexService,
	usersService services.UsersService, contractsMgr contracts.Manager, ethClient bind.ContractBackend) *TokenExchangeController {
	return &TokenExchangeController{
		logger:       logger,
		settings:     settings,
		dexService:   dexService,
		usersService: usersService,
		ctmr:         contractsMgr,
		ethClient:    ethClient,
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

	// TODO(elffjs): If the whitelist is going to stick around, then we can probably pre-construct these.
	m, err := t.ctmr.GetMultiPrivilege(nftAddr.Hex(), t.ethClient)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	s, err := t.ctmr.GetSacd(t.settings.ContractAddressSacd, t.ethClient)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Could not connect to blockchain node")
	}

	ethAddr := api.GetUserEthAddr(c)
	if ethAddr == nil {
		// If eth addr not in JWT, use userID to fetch user
		userID := api.GetUserID(c)
		user, err := t.usersService.GetUserByID(c.Context(), userID)
		if err != nil {
			// TODO(elffjs): If there's no record here, it's a client error.
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user by ID")
		}
		if user.EthereumAddress == nil || !common.IsHexAddress(*user.EthereumAddress) {
			return fiber.NewError(fiber.StatusBadRequest, "No Ethereum address in JWT or on record.")
		}
		e := common.HexToAddress(*user.EthereumAddress)
		ethAddr = &e
	}

	resPermRecord, err := s.CurrentPermissionRecord(nil, nftAddr, big.NewInt(pr.TokenID), *ethAddr)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Fetch the JSON content from IPFS
	jsonContent, err := t.fetchFromIPFS(resPermRecord.Source)
	if err != nil {
		t.logger.Warn().Err(err).Msg("Failed to fetch JSON from IPFS")
		// Proceed with other checks if IPFS fetch fails
	} else {
		hasPermFromSacdDoc, err := t.checkPermissionsFromSacdDoc(jsonContent, pr.Privileges, ethAddr.Hex())
		if err != nil {
			t.logger.Warn().Err(err).Msg("Failed to validate IPFS JSON")
		} else if hasPermFromSacdDoc {
			return t.createAndReturnToken(c, pr, ethAddr)
		}
	}

	// If the user doesn't have all permissions from IPFS doc, check bitstring
	// Convert pr.Privileges to 2-bit array format
	privilegesBitArray := intArrayTo2BitArray(pr.Privileges, 128) // Assuming max privilege is 128

	hasPerm, err := s.HasPermissions(nil, nftAddr, big.NewInt(pr.TokenID), *ethAddr, privilegesBitArray)
	if err != nil {
		// TODO should we just log it?
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if hasPerm {
		return t.createAndReturnToken(c, pr, ethAddr)
	}

	// If the user doesn't have all permissions in SACD, check the old privilege system
	for _, p := range pr.Privileges {
		if p < 0 || p >= 128 {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid permission id %d. These must be non-negative and less than 128.", p))
		}

		resMulti, err := m.HasPrivilege(nil, big.NewInt(pr.TokenID), big.NewInt(p), *ethAddr)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !resMulti {
			return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("Address %s lacks permission %d on token id %d for asset %s.", *ethAddr, p, pr.TokenID, nftAddr))
		}
	}

	return t.createAndReturnToken(c, pr, ethAddr)
}

// Helper function to create and return the token
func (t *TokenExchangeController) createAndReturnToken(c *fiber.Ctx, pr *PermissionTokenRequest, ethAddr *common.Address) error {
	aud := pr.Audience
	if len(aud) == 0 {
		aud = defaultAudience
	}

	tk, err := t.dexService.SignPrivilegePayload(c.Context(), services.PrivilegeTokenDTO{
		UserEthAddress:     ethAddr.Hex(),
		TokenID:            strconv.FormatInt(pr.TokenID, 10),
		PrivilegeIDs:       pr.Privileges,
		NFTContractAddress: pr.NFTContractAddress,
		Audience:           aud,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(PermissionTokenResponse{
		Token: tk,
	})
}

func (t *TokenExchangeController) fetchFromIPFS(cid string) (string, error) {
	// Remove the "ipfs://" prefix if it exists
	// TODO Mayber a Regex is better. We should remove "ipfs://" from the SACD source
	cid = strings.TrimPrefix(cid, "ipfs://")

	url := fmt.Sprintf("https://assets.dimo.xyz//ipfs/%s", cid)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch from IPFS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read IPFS response: %w", err)
	}

	return string(body), nil
}

func (t *TokenExchangeController) checkPermissionsFromSacdDoc(jsonSource string, requestedPrivileges []int64, granteeAddress string) (bool, error) {
	var record PermissionRecord
	if err := json.Unmarshal([]byte(jsonSource), &record); err != nil {
		return false, fmt.Errorf("invalid JSON format: %w", err)
	}

	if record.Type != "dimo.sacd" {
		return false, fmt.Errorf("invalid type: expected 'dimo.sacd', got '%s'", record.Type)
	}

	now := time.Now()
	if now.Before(record.Data.EffectiveAt) || now.After(record.Data.ExpiresAt) {
		return false, fmt.Errorf("current time is outside the effective period")
	}

	if record.Data.Grantee.Address != granteeAddress {
		return false, fmt.Errorf("grantee address mismatch")
	}

	// TODO Validate asset "did:nft:137:0x3330000000000000000000000000000000000000_31415"

	// TODO I can have a list of permissions, how to choose the right one?
	// Check permissions
	userPermissions := make(map[string]bool)
	for _, agreement := range record.Data.Agreement {
		// Check agreement type
		if agreement.Type != "permissions" {
			return false, fmt.Errorf("invalid agreement type: expected 'permissions', got '%s'", agreement.Type)
		}

		// Add permissions from this agreement
		for _, permission := range agreement.Permissions {
			userPermissions[permission.Name] = true
		}
	}

	// Check if the user has all the requested privileges
	for _, priv := range requestedPrivileges {
		permName := fmt.Sprintf("permission%d", priv)
		if !userPermissions[permName] {
			return false, fmt.Errorf("user lacks required permission: %s", permName)
		}
	}

	return true, nil
}

func intArrayTo2BitArray(indices []int64, length int) *big.Int {
	bitArray := big.NewInt(0)

	for _, index := range indices {
		if index >= 1 && index <= int64(length) {
			bitArray.SetBit(bitArray, int(index*2), 1)
			bitArray.SetBit(bitArray, int(index*2+1), 1)
		}
	}

	return bitArray
}
