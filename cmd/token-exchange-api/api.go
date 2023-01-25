package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DIMO-Network/token-exchange-api/internal/api"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	vtx "github.com/DIMO-Network/token-exchange-api/internal/controllers"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	swagger "github.com/arsmn/fiber-swagger/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	mware "github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	log "github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	jwtWare "github.com/gofiber/jwt/v3"
	"github.com/rs/zerolog"
)

func startWebAPI(ctx context.Context, logger zerolog.Logger, settings *config.Settings) {
	dxS := services.NewDexService(&logger, settings)
	userService := services.NewUsersService(&logger, settings)
	vtxController := vtx.NewTokenExchangeController(&logger, settings, dxS, userService)

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
	//cors
	app.Use(cors.New())
	// request logging
	app.Use(log.New(log.ConfigDefault))

	app.Get("/", healthCheck)

	sc := swagger.Config{}
	app.Get("/v1/swagger/*", swagger.New(sc))

	keyRefreshInterval := time.Hour
	keyRefreshUnknownKID := true
	jwtAuth := jwtWare.New(jwtWare.Config{
		KeySetURL:            settings.JWKKeySetURL,
		KeyRefreshInterval:   &keyRefreshInterval,
		KeyRefreshUnknownKID: &keyRefreshUnknownKID,
		KeyRefreshErrorHandler: func(j *jwtWare.KeySet, err error) {
			logger.Error().Err(err).Msg("Key refresh error")
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).JSON(struct {
				Message string `json:"message"`
			}{"Invalid or expired JWT"})
		},
	})

	// All api routes should be under v1
	v1Route := app.Group("/v1")
	// Token routes
	tokenRoutes := v1Route.Group("/tokens", jwtAuth)
	adWhitelist := mware.NewContractWhiteList(settings, logger)

	tokenRoutes.Post("/exchange", adWhitelist, vtxController.GetDeviceCommandPermissionWithScope)

	go serveMonitoring(settings.MonPort, &logger)

	logger.Info().Msg(settings.ServiceName + " - Server started on port " + settings.Port)
	// Start Server from a different go routine
	go func() {
		if err := app.Listen(":" + settings.Port); err != nil {
			logger.Fatal().Err(err)
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

	monApp.Get("/", func(c *fiber.Ctx) error { return nil })
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
