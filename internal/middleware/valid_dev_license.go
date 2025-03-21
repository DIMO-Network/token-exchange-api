package middleware

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/DIMO-Network/token-exchange-api/internal/middleware/dex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
)

// mobileAppAudience Audience in DIMO mobile JWT
const mobileAppAudience = "dimo-driver"

//go:generate mockgen -source valid_dev_license.go -destination mocks/valid_dev_license_mock.go
type IdentityService interface {
	IsDevLicense(ctx context.Context, ethAddr common.Address) (bool, error)
}

// NewDevLicenseValidator validates whether the jwt is coming from DIMO mobile or if it represents a valid developer license
func NewDevLicenseValidator(idSvc IdentityService, logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token, ok := c.Locals("user").(*jwt.Token)
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "failed to pull token from request context")
		}

		// get audience from claim to check if it is coming from dimo mobile
		aud, err := token.Claims.GetAudience()
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to get audience from token claims")
		}

		// no additional checks for mobile app
		// TODO(ae): add additional security here eventually
		if slices.Contains(aud, mobileAppAudience) {
			return c.Next()
		}

		// if not dimo mobile, make sure the subject is a dev license
		subj, err := token.Claims.GetSubject()
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to get subject from token claims")
		}

		decoded, err := base64.RawURLEncoding.DecodeString(subj)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to decode subject")
		}

		var user dex.User
		if err = proto.Unmarshal(decoded, &user); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "failed to parse subject")
		}

		if !common.IsHexAddress(user.UserId) {
			return fiber.NewError(fiber.StatusBadRequest, "user id is not valid hex address")
		}

		valid, err := idSvc.IsDevLicense(c.Context(), common.HexToAddress(user.UserId))
		if err != nil {
			return err
		}

		if valid {
			return c.Next()
		}

		logger.Debug().Str("subject", user.UserId).Any("audience", aud).Msg("not a dev license")
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("not a dev license: %s", user.UserId))
	}
}
