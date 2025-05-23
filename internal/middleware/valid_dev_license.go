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

const (
	// mobileAppAudience is the audience field for a DIMO mobile "user JWT".
	mobileAppAudience = "dimo-driver"

	// devLicenseKey is the context key for the developer license address.
	devLicenseKey keyType = "developerLicense"
)

type keyType string

// const

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

		clientAddress := common.HexToAddress(user.UserId)

		valid, err := idSvc.IsDevLicense(c.Context(), clientAddress)
		if err != nil {
			return err
		}

		if valid {
			c.Locals(devLicenseKey, clientAddress)
			return c.Next()
		}

		logger.Debug().Str("subject", user.UserId).Any("audience", aud).Msg("not a dev license")
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("not a dev license: %s", user.UserId))
	}
}

var zeroAddr common.Address

// GetDevLicense returns the address of the developer license making the request. If
// the request is not coming from a developer license then this function returns the
// zero address.
func GetDevLicense(c *fiber.Ctx) common.Address {
	addr, ok := c.Locals(devLicenseKey).(common.Address)
	if !ok {
		return zeroAddr
	}
	return addr
}
