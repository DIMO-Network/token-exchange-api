package api

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"

	"strconv"
)

// ErrorResponseHandler is deprecated. it doesn't log. We prefer to return an err and have the ErrorHandler in api.go handle stuff.
func ErrorResponseHandler(c *fiber.Ctx, err error, status int) error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return c.Status(status).JSON(fiber.Map{
		"errorMessage": msg,
	})
}

const ethereumAddressClaimName = "ethereum_address"

var zeroAddr common.Address

// GetUserEthAddr returns the Ethereum address in the JWT provided for the current request.
// If no address is found then this function returns a Fiber error that can be safely returned
// to the client.
func GetUserEthAddr(c *fiber.Ctx) (common.Address, error) {
	// If the Fiber middleware runs then these are safe.
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	addrClaim, ok := claims[ethereumAddressClaimName]
	if !ok {
		return zeroAddr, fiber.NewError(fiber.StatusUnauthorized, "No Ethereum address claim found.")
	}

	addrString, ok := addrClaim.(string)
	if !ok {
		return zeroAddr, fiber.NewError(fiber.StatusUnauthorized, "Ethereum address claim is not a string.")
	}

	if !common.IsHexAddress(addrString) {
		return zeroAddr, fiber.NewError(fiber.StatusUnauthorized, "Ethereum address claim is not a valid.")
	}

	return common.HexToAddress(addrString), nil
}

// ErrorHandler custom handler to log recovered errors using our logger and return json instead of string
func ErrorHandler(c *fiber.Ctx, err error, logger zerolog.Logger, environment string) error {
	code := fiber.StatusInternalServerError // Default 500 statuscode

	e, fiberTypeErr := err.(*fiber.Error)
	if fiberTypeErr {
		// Override status code if fiber.Error type
		code = e.Code
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	codeStr := strconv.Itoa(code)

	logger.Err(err).Str("httpStatusCode", codeStr).
		Str("httpMethod", c.Method()).
		Str("httpPath", c.Path()).
		Msg("caught an error from http request")
	// return an opaque error if we're in a higher level environment and we haven't specified an fiber type err.
	if !fiberTypeErr && environment == "prod" {
		err = fiber.NewError(fiber.StatusInternalServerError, "Internal error")
	}

	return c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": err.Error(),
	})
}
