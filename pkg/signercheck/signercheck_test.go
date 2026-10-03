package signercheck

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var (
	testLicense = common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	testSigner  = common.HexToAddress("0x71efD5d71a597eB6BEC28DFDB05a49283a3e20c5")
)

type fakeChecker struct {
	result Result
	err    error
	calls  int
}

func (f *fakeChecker) Check(context.Context, common.Address, common.Address) (Result, error) {
	f.calls++
	return f.result, f.err
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeEnforce, "enforce": ModeEnforce, "log": ModeLog, "off": ModeOff} {
		got, err := ParseMode(in)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err := ParseMode("Enforce")
	require.ErrorContains(t, err, "SIGNER_CHECK_MODE")
}

func TestMiddleware(t *testing.T) {
	withSigner := TokenInfo{License: testLicense, Signer: testSigner.Hex()}

	tests := []struct {
		name       string
		mode       Mode
		token      TokenInfo
		checker    *fakeChecker
		wantStatus int
		wantBody   string
		wantResult string
		wantCalls  int
	}{
		{name: "enforce allows an enabled signer", mode: ModeEnforce, token: withSigner, checker: &fakeChecker{result: Allowed}, wantStatus: 200, wantResult: "allowed", wantCalls: 1},
		{name: "enforce refuses a disabled signer", mode: ModeEnforce, token: withSigner, checker: &fakeChecker{result: Denied}, wantStatus: 403, wantBody: MessageDenied, wantResult: "denied", wantCalls: 1},
		{name: "enforce answers 503 when the check fails", mode: ModeEnforce, token: withSigner, checker: &fakeChecker{err: errors.New("rpc down")}, wantStatus: 503, wantBody: MessageUnavailable, wantResult: "error", wantCalls: 1},
		{name: "log lets a disabled signer through and counts it", mode: ModeLog, token: withSigner, checker: &fakeChecker{result: Denied}, wantStatus: 200, wantResult: "denied", wantCalls: 1},
		{name: "log lets a failed check through and counts it", mode: ModeLog, token: withSigner, checker: &fakeChecker{err: errors.New("rpc down")}, wantStatus: 200, wantResult: "error", wantCalls: 1},
		{name: "off skips the check", mode: ModeOff, token: withSigner, checker: &fakeChecker{result: Denied}, wantStatus: 200, wantResult: "skipped"},
		{name: "a token without signer_address is skipped", mode: ModeEnforce, token: TokenInfo{License: testLicense}, checker: &fakeChecker{result: Denied}, wantStatus: 200, wantResult: "skipped"},
		{name: "a token without ethereum_address is skipped", mode: ModeEnforce, token: TokenInfo{Signer: testSigner.Hex()}, checker: &fakeChecker{result: Denied}, wantStatus: 200, wantResult: "skipped"},
		{name: "a non-license is skipped", mode: ModeEnforce, token: withSigner, checker: &fakeChecker{result: NotLicense}, wantStatus: 200, wantResult: "skipped", wantCalls: 1},
		{name: "a malformed claim is refused without a check", mode: ModeEnforce, token: TokenInfo{License: testLicense, Signer: "0x1234"}, checker: &fakeChecker{result: Allowed}, wantStatus: 403, wantBody: MessageDenied, wantResult: "denied"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := "test-" + tc.name
			app := fiber.New()
			app.Get("/", Middleware(Config{
				Service: service,
				Mode:    tc.mode,
				Checker: tc.checker,
				Token:   func(*fiber.Ctx) (TokenInfo, error) { return tc.token, nil },
				Logger:  zerolog.Nop(),
			}), func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

			resp, err := app.Test(httptest.NewRequest("GET", "/", nil), -1)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, tc.wantStatus, resp.StatusCode, string(body))
			if tc.wantBody != "" {
				require.Equal(t, tc.wantBody, string(body))
			}
			require.Equal(t, tc.wantCalls, tc.checker.calls)
			require.Equal(t, 1.0, testutil.ToFloat64(checks.WithLabelValues(service, tc.wantResult)))
		})
	}
}

func TestMapClaimsToken(t *testing.T) {
	read := func(claims jwt.MapClaims) TokenInfo {
		app := fiber.New()
		var got TokenInfo
		app.Get("/", func(c *fiber.Ctx) error {
			if claims != nil {
				c.Locals("user", jwt.NewWithClaims(jwt.SigningMethodHS256, claims))
			}
			var err error
			got, err = MapClaimsToken("user")(c)
			require.NoError(t, err)
			return c.SendStatus(fiber.StatusOK)
		})
		_, err := app.Test(httptest.NewRequest("GET", "/", nil), -1)
		require.NoError(t, err)
		return got
	}

	got := read(jwt.MapClaims{
		"ethereum_address": "0x299671d2b32ed62cc61ce65d8f2b9e4f78486b37",
		"signer_address":   "0x71efd5d71a597eb6bec28dfdb05a49283a3e20c5",
	})
	require.Equal(t, TokenInfo{License: testLicense, Signer: "0x71efd5d71a597eb6bec28dfdb05a49283a3e20c5"}, got)

	require.Equal(t, TokenInfo{}, read(nil), "no token")
	require.Equal(t, TokenInfo{License: testLicense}, read(jwt.MapClaims{"ethereum_address": testLicense.Hex()}), "no signer claim")
	require.Equal(t, "invalid", read(jwt.MapClaims{"ethereum_address": testLicense.Hex(), "signer_address": 42}).Signer, "a non-string claim is malformed")
	require.Equal(t, common.Address{}, read(jwt.MapClaims{"ethereum_address": "not-an-address"}).License)
}
