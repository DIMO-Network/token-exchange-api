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

func GetUserID(c *fiber.Ctx) string {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	userID := claims["sub"].(string)
	return userID
}

func GetUserEthAddr(c *fiber.Ctx) *common.Address {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	ethAddr, ok := claims["ethereum_address"].(string)
	if !ok || !common.IsHexAddress(ethAddr) {
		return nil
	}
	e := common.HexToAddress(ethAddr)
	return &e
}

func GetClaimSubject(c *fiber.Ctx) *common.Address {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	subj, ok := claims["sub"].(string)
	if !ok || !common.IsHexAddress(subj) {
		return nil
	}
	subject := common.HexToAddress(subj)
	return &subject
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
