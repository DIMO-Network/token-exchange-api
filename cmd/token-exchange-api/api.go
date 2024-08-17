package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/common"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	vtx "github.com/DIMO-Network/token-exchange-api/internal/controllers"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

func parseContractWhitelist(rawAddrs string) ([]common.Address, error) {
	if rawAddrs == "" {
		return nil, errors.New("empty whitelist")
	}

	out := make([]common.Address, len(rawAddrs))

	for i, raw := range strings.Split(rawAddrs, ",") {
		if !common.IsHexAddress(raw) {
			return nil, fmt.Errorf("invalid contract address %q", raw)
		}
		out[i] = common.HexToAddress(raw)
	}

	return out, nil
}

func startWebAPI(ctx context.Context, logger zerolog.Logger, settings *config.Settings) {
	ctrAddressesWhitelist, err := parseContractWhitelist(settings.ContractAddressWhitelist)
	if err != nil {
		logger.Fatal().
			Err(err).
			Str("settings.ContractAddressWhitelist", settings.ContractAddressWhitelist).
			Msg("Error occurred. Invalid contract whitelist addresses")
	}

	dxS, err := services.NewDexService(&logger, settings.DexGRPCAdddress)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to construct Dex client.")
	}
	userService := services.NewUsersService(&logger, settings)
	vtxController := vtx.NewTokenExchangeController(&logger, dxS, userService, ctrAddressesWhitelist)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			logger.Printf("Errror occurred %s", err)
			return api.ErrorHandler(c, err, logger, settings.Environment)
		},
		DisableStartupMessage: true,
		ReadBufferSize:        16000,
		BodyLimit:             10 * 1024 * 1024,
	})

	app.Use(fiberrecover.New(fiberrecover.Config{
		Next:              nil,
		EnableStackTrace:  true,
		StackTraceHandler: nil,
	}))

	app.Get("/", healthCheck)

	sc := swagger.Config{}
	app.Get("/v1/swagger/*", swagger.New(sc))

	jwtAuth := jwtware.New(jwtware.Config{
		JWKSetURLs: []string{settings.JWKKeySetURL},
	})

	// All api routes should be under v1
	v1Route := app.Group("/v1")
	// Token routes
	tokenRoutes := v1Route.Group("/tokens", jwtAuth)

	tokenRoutes.Post("/exchange", vtxController.GetDeviceCommandPermissionWithScope)

	go serveMonitoring(settings.MonPort, &logger) //nolint

	logger.Info().Msg(settings.ServiceName + " - Server started on port " + settings.Port)
	// Start Server from a different go routine
	go func() {
		if err := app.Listen(":" + settings.Port); err != nil {
			logger.Fatal().Err(err).Send()
		}
	}()

	c := make(chan os.Signal, 1)                    // Create channel to signify a signal being sent with length of 1
	signal.Notify(c, os.Interrupt, syscall.SIGTERM) // When an interrupt or termination signal is sent, notify the channel
	<-c                                             // This blocks the main thread until an interrupt is received
	logger.Info().Msg("Gracefully shutting down and running cleanup tasks...")
	_ = ctx.Done()
	_ = app.Shutdown()
}

func serveMonitoring(port string, logger *zerolog.Logger) (*fiber.App, error) {
	logger.Info().Str("port", port).Msg("Starting monitoring web server.")

	monApp := fiber.New(fiber.Config{DisableStartupMessage: true})

	monApp.Get("/", func(*fiber.Ctx) error { return nil })
	monApp.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	go func() {
		if err := monApp.Listen(":" + port); err != nil {
			logger.Fatal().Err(err).Str("port", port).Msg("Failed to start monitoring web server.")
		}
	}()

	return monApp, nil
}

func healthCheck(c *fiber.Ctx) error {
	res := map[string]interface{}{
		"data": "Server is up and running",
	}

	if err := c.JSON(res); err != nil {
		return err
	}

	return nil
}
