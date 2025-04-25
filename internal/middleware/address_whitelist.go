package middleware

import (
	"regexp"
	"slices"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// ReqBody is controllers.PermissionTokenRequest with the only field
// we care about.
type ReqBody struct {
	NFTContractAddress string `json:"nftContractAddress"`
}

var AddressRegex = regexp.MustCompile("^0x[a-f0-9]{40}$")

func NewContractWhiteList(settings *config.Settings, logger zerolog.Logger, ctrWhitelist []string) fiber.Handler {
	l := logger.With().
		Str("feature", "middleware").
		Str("name", "address_whitelist").
		Logger()

	wl := make([]common.Address, len(ctrWhitelist))
	for i, s := range ctrWhitelist {
		wl[i] = common.HexToAddress(s)
	}

	return func(c *fiber.Ctx) error {
		var body ReqBody
		if err := c.BodyParser(&body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
		}

		if !common.IsHexAddress(body.NFTContractAddress) {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid contract address.")
		}

		contract := common.HexToAddress(body.NFTContractAddress)

		if !slices.Contains(wl, contract) {
			l.Info().
				Str("settings.ContractAddressWhitelist", settings.ContractAddressWhitelist).
				Str("requestContract", body.NFTContractAddress).
				Msg("Invalid contract address")
			return fiber.NewError(fiber.StatusForbidden, "Contract address not whitelisted.")
		}

		return c.Next()
	}
}
