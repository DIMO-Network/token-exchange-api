package main

import (
	"context"
	"os"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/rs/zerolog"
)

// @title                      DIMO Token Exchange API
// @version                    1.0
// @BasePath                   /v1
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
func main() {
	gitSha1 := os.Getenv("GIT_SHA1")
	ctx := context.Background()
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "devices-api").
		Str("git-sha1", gitSha1).
		Logger()

	settings, err := shared.LoadConfig[config.Settings]("settings.yaml")
	if err != nil {
		logger.Fatal().Err(err).Msg("could not load settings")
	}
	level, err := zerolog.ParseLevel(settings.LogLevel)
	if err != nil {
		logger.Fatal().Err(err).Msgf("could not parse LOG_LEVEL: %s", settings.LogLevel)
	}
	zerolog.SetGlobalLevel(level)

	deps := newDependencyContainer(&settings, logger)
	startWebAPI(ctx, *deps.logger, &settings)
}

// dependencyContainer way to hold different dependencies we need for our app. We could put all our deps and follow this pattern for everything.
type dependencyContainer struct {
	settings *config.Settings
	logger   *zerolog.Logger
}

func newDependencyContainer(settings *config.Settings, logger zerolog.Logger) dependencyContainer {
	return dependencyContainer{
		settings: settings,
		logger:   &logger,
	}
}
