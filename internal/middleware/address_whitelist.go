package middleware

import (
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
)

type ReqBody struct {
	NFTContractAddress string `json:"nftContractAddress"`
}

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
