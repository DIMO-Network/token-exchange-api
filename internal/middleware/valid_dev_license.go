package middleware

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

// MobileAppAudience Audience in DIMO mobile JWT
const MobileAppAudience = "dimo-driver"
const MobileAppDeveloperLicense = "0x" //TODO(ae)

// NewDevLicenseValidator validates whether the jwt is coming from DIMO mobile or if it represents a valid developer license
func NewDevLicenseValidator(settings *config.Settings, logger zerolog.Logger, idSvc services.IdentityService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return fiber.NewError(fiber.StatusBadRequest, "invalid authorization header")
		}

		tk := strings.TrimPrefix(authHeader, "Bearer ")
		token, _, err := new(jwt.Parser).ParseUnverified(tk, jwt.MapClaims{})
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid authorization token")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "failed to parse claims")
		}

		subj, ok := claims["sub"].(string)
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "invalid type in claim")
		}

		aud, ok := claims["aud"].(string)
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "invalid type found in claim")
		}

		// TODO(ae) also check for mobile dev license?
		if aud == MobileAppAudience {
			return c.Next()
		}

		decoded, err := base64.RawStdEncoding.DecodeString(subj)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}

		subject := strings.Trim(string(
			bytes.TrimSpace(
				bytes.TrimSuffix(decoded, []byte("\x12\x04web3")),
			),
		), "*")

		valid, err := idSvc.IsDevLicense(c.Context(), common.HexToAddress(subject))
		if err != nil {
			return err
		}

		if valid {
			if subject != aud {
				logger.Debug().Str("subject", subject).Str("audience", aud).Msg("developer jwt sub and aud do not match")
			}
			return c.Next()
		}

		logger.Debug().Msg("invalid dev license requesting access")
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("invalid dev license requesting access: %s", subject))
	}
}
