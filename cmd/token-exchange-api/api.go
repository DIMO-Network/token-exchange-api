package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	vtx "github.com/DIMO-Network/token-exchange-api/internal/controllers"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/DIMO-Network/token-exchange-api/internal/services/access"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

func getContractWhitelistedAddresses(wAddrs string) ([]string, error) {
	if wAddrs == "" {
		return nil, errors.New("empty whitelist")
	}

	w := strings.Split(wAddrs, ",")

	for _, v := range w {
		if !common.IsHexAddress(v) {
			return nil, fmt.Errorf("invalid contract address %q", v)
		}
	}

	return w, nil
}

func startWebAPI(ctx context.Context, logger zerolog.Logger, settings *config.Settings) {
	dexSvc, err := services.NewDexClient(&logger, settings.DexGRPCAdddress)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create dex grpc client")
	}

	ethClient, err := ethclient.Dial(settings.BlockchainNodeURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to dial Ethereum RPC.")
	}

	ipfsService, err := services.NewIPFSClient(&logger, settings.IPFSBaseURL, settings.IPFSTimeout)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create IPFS client")
	}

	sacdContract, err := sacd.NewSacd(settings.ContractAddressSacd, ethClient)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to blockchain node")
	}

	accessService, err := access.NewAccessService(ipfsService, sacdContract)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create access service")
	}

	vtxController, err := vtx.NewTokenExchangeController(&logger, settings, dexSvc, accessService)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize token exchange controller")
	}
	idSvc := services.NewIdentityController(&logger, settings)

	devLicenseMiddleware := middleware.NewDevLicenseValidator(idSvc, logger)

	ctrAddressesWhitelist, err := getContractWhitelistedAddresses(settings.ContractAddressWhitelist)
	if err != nil {
		logger.Fatal().
			Err(err).
			Str("settings.ContractAddressWhitelist", settings.ContractAddressWhitelist).
			Msg("Error occurred. Invalid contract whitelist addresses")
	}

	app := fiber.New(fiber.Config{
		ErrorHandler:          ErrorHandler,
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

	handlers := []fiber.Handler{jwtAuth, devLicenseMiddleware}

	// All api routes should be under v1
	v1Route := app.Group("/v1")
	// Token routes
	tokenRoutes := v1Route.Group("/tokens", handlers...)
	ctrWhitelistWare := middleware.NewContractWhiteList(settings, logger, ctrAddressesWhitelist)

	tokenRoutes.Post("/exchange", ctrWhitelistWare, vtxController.ExchangeToken)

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

type codeResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorHandler custom handler to log recovered errors using our logger and return json instead of string
func ErrorHandler(ctx *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError // Default 500 statuscode
	message := "Internal error."

	var fiberErr *fiber.Error
	var richErr richerrors.Error
	if errors.As(err, &fiberErr) {
		code = fiberErr.Code
		message = fiberErr.Message
	} else if errors.As(err, &richErr) {
		message = richErr.ExternalMsg
		if richErr.Code != 0 {
			code = richErr.Code
		}
	}

	// log all errors except 404
	if code != fiber.StatusNotFound {
		logger := zerolog.Ctx(ctx.UserContext())
		logger.Err(err).Int("httpStatusCode", code).
			Str("httpPath", strings.TrimPrefix(ctx.Path(), "/")).
			Str("httpMethod", ctx.Method()).
			Msg("caught an error from http request")
	}

	return ctx.Status(code).JSON(codeResp{Code: code, Message: message})
}
