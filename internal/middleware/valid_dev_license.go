package middleware

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

// mobileAppAudience Audience in DIMO mobile JWT
const mobileAppAudience = "dimo-driver"

// NewDevLicenseValidator validates whether the jwt is coming from DIMO mobile or if it represents a valid developer license
func NewDevLicenseValidator(logger zerolog.Logger, idSvc services.IdentityService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token, ok := c.Locals("user").(*jwt.Token)
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "failed to pull token from request context")
		}

		subj, err := token.Claims.GetSubject()
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to get subject from token claims")
		}

		aud, err := token.Claims.GetAudience()
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to get audience from token claims")
		}

		if slices.Contains(aud, mobileAppAudience) {
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
			if !slices.Contains(aud, subject) {
				logger.Debug().Str("subject", subject).Any("aud", aud).Msg("developer jwt sub and aud do not match")
			}
			return c.Next()
		}

		logger.Debug().Msg("invalid dev license requesting access")
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("invalid dev license requesting access: %s", subject))
	}
}
