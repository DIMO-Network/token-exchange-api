package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/DIMO-Network/server-garage/pkg/monserver"
	"github.com/DIMO-Network/server-garage/pkg/runner"
	"github.com/DIMO-Network/shared/pkg/settings"
	_ "github.com/DIMO-Network/token-exchange-api/docs"
	"github.com/DIMO-Network/token-exchange-api/internal/app"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// @title                      DIMO Token Exchange API
// @version                    1.0
// @BasePath                   /v1
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("app", "token-exchange-api").Logger()
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) == 40 {
				logger = logger.With().Str("commit", s.Value[:7]).Logger()
				break
			}
		}
	}
	zerolog.DefaultContextLogger = &logger

	mainCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-mainCtx.Done()
		logger.Info().Msg("Received signal, shutting down...")
		cancel()
	}()
	runnerGroup, runnerCtx := errgroup.WithContext(mainCtx)
	settings, err := settings.LoadConfig[config.Settings]("settings.yaml")
	if err != nil {
		logger.Fatal().Err(err).Msg("could not load settings")
	}
	level, err := zerolog.ParseLevel(settings.LogLevel)
	if err != nil {
		logger.Fatal().Err(err).Msgf("could not parse LOG_LEVEL: %s", settings.LogLevel)
	}
	zerolog.SetGlobalLevel(level)

	monApp := monserver.NewMonitoringServer(&logger, settings.EnablePprof)
	logger.Info().Str("port", strconv.Itoa(settings.MonPort)).Msgf("Starting monitoring server")
	runner.RunHandler(runnerCtx, runnerGroup, monApp, ":"+strconv.Itoa(settings.MonPort))

	webServer, rpcServer, err := app.CreateServers(logger, &settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create servers.")
	}

	logger.Info().Str("port", strconv.Itoa(settings.Port)).Msgf("Starting web server")
	runner.RunFiber(runnerCtx, runnerGroup, webServer, ":"+strconv.Itoa(settings.Port))

	logger.Info().Str("port", strconv.Itoa(settings.GRPCPort)).Msgf("Starting gRPC server")
	runner.RunGRPC(runnerCtx, runnerGroup, rpcServer, ":"+strconv.Itoa(settings.GRPCPort))

	err = runnerGroup.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatal().Err(err).Msg("Server shut down due to an error.")
	}
	logger.Info().Msg("Server shut down.")

}
