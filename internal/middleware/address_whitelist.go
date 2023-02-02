package middleware

import (
	"regexp"
	"strings"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
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

	return func(c *fiber.Ctx) error {
		body := &ReqBody{}
		if err := c.BodyParser(body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
		}

		nftContractAddress := strings.ToLower(body.NFTContractAddress)

		if !AddressRegex.MatchString(nftContractAddress) {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid contract address provided")
		}

		if !slices.Contains(ctrWhitelist, body.NFTContractAddress) {
			l.Info().
				Str("settings.ContractAddressWhitelist", settings.ContractAddressWhitelist).
				Str("requestContract", body.NFTContractAddress).
				Msg("Invalid contract address")
			return fiber.NewError(fiber.StatusUnauthorized, "Contract Address is not authorized!")
		}

		return c.Next()
	}
}