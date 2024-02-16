package api

import (
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
	"os"
	"testing"

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
		expectedAddr *common.Address
		expectingNil bool
	}{
		{
			name: "Token With Ethereum Address",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": "0x20Ca3bE69a8B95D3093383375F0473A8c6341727",
			},
			expectedAddr: &common.Address{0x20, 0xca, 0x3b, 0xe6, 0x9a, 0x8b, 0x95, 0xd3, 0x09, 0x33, 0x83, 0x37, 0x5f, 0x04, 0x73, 0xa8, 0xc6, 0x34, 0x17, 0x27},
			expectingNil: false,
		},
		{
			name:         "Token Without Ethereum Address",
			tokenClaims:  jwt.MapClaims{},
			expectingNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tc.tokenClaims,
			}
			ctx.Locals("user", token)

			result := GetUserEthAddr(ctx)

			if tc.expectingNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.expectedAddr, result)
			}
		})
	}

	logger.Info().Msg("TestGetUserEthAddr completed successfully")
}
