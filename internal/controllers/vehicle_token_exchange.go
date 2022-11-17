package controllers

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog"
)

func NewVehicleTokenExchangeController(logger *zerolog.Logger) *VehicleTokenExchangeController {
	return &VehicleTokenExchangeController{logger: logger}
}

type VehicleTokenExchangeController struct {
	logger *zerolog.Logger
}

func (v VehicleTokenExchangeController) TestProtectedRoute(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	log.Printf("%+v", claims)
	userID := claims["sub"].(string)

	log.Println(userID)

	return c.JSON(fiber.Map{
		"userID": userID,
	})
}
