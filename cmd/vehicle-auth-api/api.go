package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/DIMO-Network/token-exchange-service/internal/api"
	"github.com/DIMO-Network/token-exchange-service/internal/config"
	vtx "github.com/DIMO-Network/token-exchange-service/internal/controllers"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	log "github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
)

func startWebAPI(ctx context.Context, logger zerolog.Logger, settings *config.Settings) {

	vtxController := vtx.NewVehicleTokenExchangeController(&logger, settings)

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

	// application routes
	app.Get("/", healthCheck)

	/* keyRefreshInterval := time.Hour
	keyRefreshUnknownKID := true
	jwtAuth := jwtware.New(jwtware.Config{
		KeySetURL:            settings.JwtKeySetURL,
		KeyRefreshInterval:   &keyRefreshInterval,
		KeyRefreshUnknownKID: &keyRefreshUnknownKID,
		KeyRefreshErrorHandler: func(j *jwtware.KeySet, err error) {
			logger.Error().Err(err).Msg("Key refresh error")
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).JSON(struct {
				Message string `json:"message"`
			}{"Invalid or expired JWT"})
		},
	}) */
	// All api routes should be under v1
	v1Route := app.Group("/v1")
	// Token routes
	// tokenRoutes := v1Route.Group("/tokens", jwtAuth)
	tokenRoutes := v1Route.Group("/tokens")
	tokenRoutes.Post("/exchange", vtxController.GetVehicleCommandPermissionWithScope)

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

func healthCheck(c *fiber.Ctx) error {
	res := map[string]interface{}{
		"data": "Server is up and running",
	}

	if err := c.JSON(res); err != nil {
		return err
	}

	return nil
}
