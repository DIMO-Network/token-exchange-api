package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"github.com/DIMO-Network/token-exchange-api/internal/middleware/dex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
)

type keyType string

const (
	// mobileAppAudience is the audience field for a DIMO mobile "user JWT".
	mobileAppAudience = "dimo-driver"

	// responseSubjectKey is the Fiber context key for the "result subject", the JWT
	// "sub" field in the token returned from this service.
	responseSubjectKey keyType = "responseSubject"
)

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
			c.Locals(responseSubjectKey, mobileAppAudience)
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
			c.Locals(responseSubjectKey, clientAddress.Hex())
			return c.Next()
		}

		logger.Debug().Str("subject", user.UserId).Any("audience", aud).Msg("not a dev license")
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("not a dev license: %s", user.UserId))
	}
}

// GetResponseSubject returns the checksummed address of the developer license making
// the request, to be used as the JWT sub field of the token in the response to the
// client.
//
// The only exception to this occurs when the request emanates from the mobile
// app, in which case the subject returned is "dimo-driver". This legacy mode will
// disappear in the near future.
func GetResponseSubject(c *fiber.Ctx) (string, error) {
	addr, ok := c.Locals(responseSubjectKey).(string)
	if !ok {
		return "", ErrNoSubject
	}
	return addr, nil
}

// ErrNoSubject indicates that the subject of the token in the response
// was not found in the request context. This suggests that the dev license
// middleware was skipped or has a bug.
var ErrNoSubject = errors.New("no subject value found in request context")
