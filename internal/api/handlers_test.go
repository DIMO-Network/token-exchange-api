package api

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestGetUserEthAddr(t *testing.T) {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	var fastReqCtx fasthttp.RequestCtx
	req := &fastReqCtx.Request
	req.Header.SetMethod(fiber.MethodGet)
	req.SetRequestURI("/")

	app := fiber.New()
	ctx := app.AcquireCtx(&fastReqCtx)
	defer app.ReleaseCtx(ctx)

	tests := []struct {
		name         string
		tokenClaims  jwt.MapClaims
		expectedAddr common.Address
		expectingErr bool
	}{
		{
			name: "Token With Ethereum Address",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": "0x20Ca3bE69a8B95D3093383375F0473A8c6341727",
			},
			expectedAddr: common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727"),
			expectingErr: false,
		},
		{
			name: "Token with Ethereum address claim, wrong type",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": 5,
			},
			expectingErr: true,
		},
		{
			name: "Token with Ethereum address claim, string that isn't a Hex address",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": "k5",
			},
			expectingErr: true,
		},
		{
			name:         "Token Without Ethereum Address",
			tokenClaims:  jwt.MapClaims{},
			expectingErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tc.tokenClaims,
			}
			ctx.Locals("user", token)

			result, err := GetUserEthAddr(ctx)

			if tc.expectingErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedAddr, result)
			}
		})
	}

	logger.Info().Msg("TestGetUserEthAddr completed successfully")
}
