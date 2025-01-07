package middleware

import (
	"fmt"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// MobileAppAudience Audience in DIMO mobile JWT
const MobileAppAudience = "DIMO-driver"

// NewDevLicenseValidator validates whether the jwt is coming from DIMO mobile or if it represents a valid developer license
func NewDevLicenseValidator(settings *config.Settings, logger zerolog.Logger, idSvc services.IdentityService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// all JWTs coming from DIMO mobile are valid (for now)
		jwtAudience := api.GetAudience(c)
		if *jwtAudience == MobileAppAudience {
			return c.Next()
		}

		jwtSubj := api.GetSubject(c)
		valid, err := idSvc.IsDevLicense(c.Context(), common.HexToAddress(*jwtSubj))
		if err != nil {
			return err
		}

		if valid {
			if *jwtSubj == *jwtAudience {
				logger.Debug().Str("subject", *jwtSubj).Str("audience", *jwtAudience).Msg("developer jwt sub and aud do not match")
			}
			return c.Next()
		}

		logger.Debug().Str("subject", *jwtSubj).Str("audience", *jwtAudience).Msg("invalid dev license requesting access")
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("invalid dev license requesting access: %s", *jwtSubj))
	}
}
