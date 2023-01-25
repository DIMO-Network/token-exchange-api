package middleware

import (
	"strings"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
)

type dependencies struct {
	settings *config.Settings
	logger   zerolog.Logger
}

type ReqBody struct {
	NFTContractAddress string `json:"nftContractAddress"`
}

func NewContractWhiteList(settings *config.Settings, logger zerolog.Logger) fiber.Handler {
	l := logger.With().
		Str("feature", "middleware").
		Str("name", "address_whitelist").
		Logger()

	cfg := dependencies{
		settings: settings,
		logger:   l,
	}

	return func(c *fiber.Ctx) error {
		body := &ReqBody{}
		if err := c.BodyParser(body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Couldn't parse request body.")
		}

		whitelist := cfg.settings.ContractAddressWhitelist
		if whitelist == "" {
			cfg.logger.Debug().Str("settings.ContractAddressWhitelist", cfg.settings.ContractAddressWhitelist)
			return fiber.NewError(fiber.StatusInternalServerError, "Error occurred, could not complete request.")
		}

		wAddrs := strings.Split(whitelist, ",")
		if !slices.Contains(wAddrs, body.NFTContractAddress) {
			cfg.logger.Error().
				Str("settings.ContractAddressWhitelist", cfg.settings.ContractAddressWhitelist).
				Str("Contract Address in request", body.NFTContractAddress)
			return fiber.NewError(fiber.StatusUnauthorized, "Contract Address is not authorized!")
		}

		return c.Next()
	}
}
