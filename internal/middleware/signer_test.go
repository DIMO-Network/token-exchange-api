package middleware_test

import (
	"encoding/base64"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware/dex"
	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
)

//go:generate go tool mockgen -source ../../pkg/signercheck/signercheck.go -destination ./signercheck_mock_test.go -package middleware_test
//go:generate go tool mockgen -source ./valid_dev_license.go -destination ./valid_dev_license_mock_test.go -package middleware_test

var (
	license = common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	signer  = common.HexToAddress("0x71efD5d71a597eB6BEC28DFDB05a49283a3e20c5")
	user    = common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")
)

func licenseClaims(t *testing.T, extra jwt.MapClaims) jwt.MapClaims {
	t.Helper()
	sub, err := proto.Marshal(&dex.User{ConnId: "web3", UserId: license.Hex()})
	require.NoError(t, err)
	claims := jwt.MapClaims{
		"aud":              license.Hex(),
		"sub":              base64.RawURLEncoding.EncodeToString(sub),
		"ethereum_address": license.Hex(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

// serveExchangeChain mounts the same chain createHTTPServer builds after jwtAuth:
// NewDevLicenseValidator, then the signer check keyed on ethereum_address.
func serveExchangeChain(t *testing.T, ident middleware.IdentityService, checker signercheck.Checker, claims jwt.MapClaims) (int, string) {
	t.Helper()
	app := fiber.New()
	app.Get("/",
		func(c *fiber.Ctx) error {
			c.Locals("user", jwt.NewWithClaims(jwt.SigningMethodHS256, claims))
			return c.Next()
		},
		middleware.NewDevLicenseValidator(ident, zerolog.Nop()),
		signercheck.Middleware(signercheck.Config{
			Service: "token-exchange-api-test",
			Mode:    signercheck.ModeEnforce,
			Checker: checker,
			Token:   signercheck.MapClaimsToken("user"),
			Logger:  zerolog.Nop(),
		}),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/", nil), -1)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func TestSignerCheckOnExchange(t *testing.T) {
	tests := []struct {
		name       string
		claims     jwt.MapClaims
		setup      func(ident *MockIdentityService, checker *MockChecker)
		wantStatus int
		wantBody   string
	}{
		{
			name:   "license token with an enabled signer passes",
			claims: licenseClaims(t, jwt.MapClaims{"signer_address": signer.Hex()}),
			setup: func(ident *MockIdentityService, checker *MockChecker) {
				ident.EXPECT().IsDevLicense(gomock.Any(), license).Return(true, nil)
				checker.EXPECT().Check(gomock.Any(), license, signer).Return(signercheck.Allowed, nil)
			},
			wantStatus: fiber.StatusOK,
		},
		{
			name:   "license token with a disabled signer is refused",
			claims: licenseClaims(t, jwt.MapClaims{"signer_address": signer.Hex()}),
			setup: func(ident *MockIdentityService, checker *MockChecker) {
				ident.EXPECT().IsDevLicense(gomock.Any(), license).Return(true, nil)
				checker.EXPECT().Check(gomock.Any(), license, signer).Return(signercheck.Denied, nil)
			},
			wantStatus: fiber.StatusForbidden,
			wantBody:   signercheck.MessageDenied,
		},
		{
			name: "mobile-audience token for a license is checked",
			claims: jwt.MapClaims{
				"aud":              "dimo-driver",
				"ethereum_address": license.Hex(),
				"signer_address":   signer.Hex(),
			},
			setup: func(_ *MockIdentityService, checker *MockChecker) {
				checker.EXPECT().Check(gomock.Any(), license, signer).Return(signercheck.Denied, nil)
			},
			wantStatus: fiber.StatusForbidden,
			wantBody:   signercheck.MessageDenied,
		},
		{
			name: "mobile-audience token for a non-license passes",
			claims: jwt.MapClaims{
				"aud":              "dimo-driver",
				"ethereum_address": user.Hex(),
				"signer_address":   signer.Hex(),
			},
			setup: func(_ *MockIdentityService, checker *MockChecker) {
				checker.EXPECT().Check(gomock.Any(), user, signer).Return(signercheck.NotLicense, nil)
			},
			wantStatus: fiber.StatusOK,
		},
		{
			name:   "license token without signer_address passes without a check",
			claims: licenseClaims(t, nil),
			setup: func(ident *MockIdentityService, _ *MockChecker) {
				ident.EXPECT().IsDevLicense(gomock.Any(), license).Return(true, nil)
			},
			wantStatus: fiber.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ident := NewMockIdentityService(ctrl)
			checker := NewMockChecker(ctrl)
			tc.setup(ident, checker)

			status, body := serveExchangeChain(t, ident, checker, tc.claims)

			require.Equal(t, tc.wantStatus, status, body)
			if tc.wantBody != "" {
				require.Equal(t, tc.wantBody, body)
			}
		})
	}
}
