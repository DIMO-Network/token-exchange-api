package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/shared/pkg/middleware/metrics"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/template"
	"github.com/DIMO-Network/token-exchange-api/internal/controllers/httpcontroller"
	"github.com/DIMO-Network/token-exchange-api/internal/controllers/rpc"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/DIMO-Network/token-exchange-api/internal/services/access"
	txgrpc "github.com/DIMO-Network/token-exchange-api/pkg/grpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// CreateServers creates the servers for the application
func CreateServers(logger zerolog.Logger, settings *config.Settings) (*fiber.App, *grpc.Server, error) {
	dexSvc, err := services.NewDexClient(&logger, settings.DexGRPCAdddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dex grpc client: %w", err)
	}

	ethClient, err := ethclient.Dial(settings.BlockchainNodeURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial Ethereum RPC: %w", err)
	}

	ipfsService, err := services.NewIPFSClient(&logger, settings.IPFSBaseURL, settings.IPFSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IPFS client: %w", err)
	}

	sacdContract, err := sacd.NewSacd(settings.ContractAddressSacd, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to blockchain node: %w", err)
	}

	templateContract, err := template.NewTemplate(settings.ContractAddressTemplate, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to blockchain node: %w", err)
	}

	accessService, err := access.NewAccessService(ipfsService, sacdContract, templateContract, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create access service: %w", err)
	}

	app, err := createHTTPServer(logger, settings, dexSvc, accessService)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create http server: %w", err)
	}

	grpcServer := createGRPCServer(rpc.NewTokenExchangeServer(accessService))

	return app, grpcServer, nil
}

func createHTTPServer(logger zerolog.Logger, settings *config.Settings, dexSvc *services.DexClient, accessService *access.Service) (*fiber.App, error) {
	httpCtrl, err := httpcontroller.NewTokenExchangeController(settings, dexSvc, accessService)
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

	tokenRoutes.Post("/exchange", ctrWhitelistWare, httpCtrl.ExchangeToken)

	return app, nil
}

func createGRPCServer(rpcCtrl *rpc.TokenExchangeServer) *grpc.Server {
	grpcPanic := metrics.GRPCPanicker{}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			// metrics.GRPCMetricsAndLogMiddleware(logger),
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanic.GRPCPanicRecoveryHandler)),
		)),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)
	txgrpc.RegisterTokenExchangeServiceServer(server, rpcCtrl)
	return server
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
