// Package signercheck refuses developer JWTs whose license signer (API key) has been
// disabled since the token was minted. It holds what every DIMO service shares: the
// SIGNER_CHECK_MODE setting, the signer_check_total metric, a Fiber middleware, and a
// client for token-exchange-api's SignerCheck gRPC.
package signercheck

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

// Mode is the SIGNER_CHECK_MODE setting.
type Mode string

const (
	// ModeEnforce refuses disabled signers. It is the default.
	ModeEnforce Mode = "enforce"
	// ModeLog runs the check, logs and counts what it would refuse, and refuses nothing.
	ModeLog Mode = "log"
	// ModeOff skips the check.
	ModeOff Mode = "off"
)

// ParseMode reads SIGNER_CHECK_MODE. Empty means enforce.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "", ModeEnforce:
		return ModeEnforce, nil
	case ModeLog, ModeOff:
		return Mode(s), nil
	default:
		return "", fmt.Errorf("SIGNER_CHECK_MODE must be enforce, log or off, got %q", s)
	}
}

// Result is the outcome of checking a signer against a license.
type Result int

const (
	// Allowed means signer is an enabled signer on the license.
	Allowed Result = iota
	// Denied means it isn't.
	Denied
	// NotLicense means the address isn't a developer license, so there is nothing to check.
	NotLicense
)

// Checker checks whether signer may still act for license.
type Checker interface {
	Check(ctx context.Context, license, signer common.Address) (Result, error)
}

const (
	// MessageDenied is the 403 body for a disabled signer.
	MessageDenied = "signer no longer authorized for this license"
	// MessageUnavailable is the 503 body when the check can't complete.
	MessageUnavailable = "could not verify signer"
)

const (
	resultAllowed = "allowed"
	resultDenied  = "denied"
	resultError   = "error"
	resultSkipped = "skipped"
)

var checks = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "signer_check_total",
	Help: "Developer JWT signer checks by service and result (allowed, denied, error, skipped).",
}, []string{"service", "result"})

// TokenInfo is what the middleware reads from the request's already-verified JWT.
type TokenInfo struct {
	// License is the ethereum_address claim; the zero address when it is missing.
	License common.Address
	// Signer is the signer_address claim as sent; empty when it is missing.
	Signer string
	// IssuedAt is the iat claim; the zero time when it is missing.
	IssuedAt time.Time
}

// Config configures Middleware.
type Config struct {
	// Service is the metric's service label, e.g. "vehicle-triggers-api".
	Service string
	Mode    Mode
	Checker Checker
	// Token reads the request's verified JWT. Mount the middleware after the JWT middleware.
	Token func(c *fiber.Ctx) (TokenInfo, error)
	// ClaimRequiredAfter, when set, refuses license tokens issued after it that lack
	// signer_address (SIGNER_CLAIM_REQUIRED_AFTER). Only token-exchange-api sets it.
	ClaimRequiredAfter time.Time
	// IsLicense reports whether an address is a developer license. Required with
	// ClaimRequiredAfter.
	IsLicense func(ctx context.Context, addr common.Address) (bool, error)
	Logger    zerolog.Logger
}

// Middleware checks the request's developer JWT whenever it carries signer_address, and
// acts on the answer according to cfg.Mode.
func Middleware(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Mode == ModeOff {
			checks.WithLabelValues(cfg.Service, resultSkipped).Inc()
			return c.Next()
		}
		tok, err := cfg.Token(c)
		if err != nil {
			return err
		}
		if tok.License == (common.Address{}) {
			checks.WithLabelValues(cfg.Service, resultSkipped).Inc()
			return c.Next()
		}
		ctx := c.UserContext()

		if tok.Signer == "" {
			if cfg.ClaimRequiredAfter.IsZero() || !tok.IssuedAt.After(cfg.ClaimRequiredAfter) {
				checks.WithLabelValues(cfg.Service, resultSkipped).Inc()
				return c.Next()
			}
			isLicense, err := cfg.IsLicense(ctx, tok.License)
			if err != nil {
				// Every claimless token after the cutoff needs this lookup, mobile users' included
				// (their ethereum_address is a wallet, never a license). The cutoff only backstops a
				// dex path that forgets the claim, so an Identity outage counts as an error and the
				// request goes through instead of refusing every one of them.
				checks.WithLabelValues(cfg.Service, resultError).Inc()
				cfg.Logger.Warn().Err(err).
					Str("service", cfg.Service).
					Str("license", tok.License.Hex()).
					Msg("Signer check could not look up the license for a claimless token; letting it through.")
				return c.Next()
			}
			if !isLicense {
				checks.WithLabelValues(cfg.Service, resultSkipped).Inc()
				return c.Next()
			}
			return cfg.refuse(c, resultDenied, tok, errors.New("license token issued after SIGNER_CLAIM_REQUIRED_AFTER without signer_address"))
		}

		if !common.IsHexAddress(tok.Signer) {
			return cfg.refuse(c, resultDenied, tok, errors.New("malformed signer_address"))
		}
		result, err := cfg.Checker.Check(ctx, tok.License, common.HexToAddress(tok.Signer))
		switch {
		case err != nil:
			return cfg.refuse(c, resultError, tok, err)
		case result == Denied:
			return cfg.refuse(c, resultDenied, tok, errors.New("signer is not enabled on the license"))
		case result == NotLicense:
			checks.WithLabelValues(cfg.Service, resultSkipped).Inc()
		default:
			checks.WithLabelValues(cfg.Service, resultAllowed).Inc()
		}
		return c.Next()
	}
}

// refuse counts and logs a denial or error, then refuses in enforce mode and lets the
// request through in log mode.
func (cfg Config) refuse(c *fiber.Ctx, result string, tok TokenInfo, reason error) error {
	checks.WithLabelValues(cfg.Service, result).Inc()
	cfg.Logger.Warn().Err(reason).
		Str("service", cfg.Service).
		Str("mode", string(cfg.Mode)).
		Str("result", result).
		Str("license", tok.License.Hex()).
		Str("signer", tok.Signer).
		Msg("Signer check refused a developer JWT.")
	if cfg.Mode != ModeEnforce {
		return c.Next()
	}
	if result == resultError {
		return fiber.NewError(fiber.StatusServiceUnavailable, MessageUnavailable)
	}
	return fiber.NewError(fiber.StatusForbidden, MessageDenied)
}

// MapClaimsToken reads TokenInfo from the *jwt.Token that gofiber/contrib/jwt stores in
// c.Locals(localsKey) with its default jwt.MapClaims. A missing token or claim yields the
// zero values, which Middleware skips. A signer_address that isn't a string reads as
// "invalid", which Middleware refuses as malformed.
func MapClaimsToken(localsKey string) func(c *fiber.Ctx) (TokenInfo, error) {
	return func(c *fiber.Ctx) (TokenInfo, error) {
		token, ok := c.Locals(localsKey).(*jwt.Token)
		if !ok {
			return TokenInfo{}, nil
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return TokenInfo{}, nil
		}
		var info TokenInfo
		if addr, ok := claims["ethereum_address"].(string); ok && common.IsHexAddress(addr) {
			info.License = common.HexToAddress(addr)
		}
		if raw, present := claims["signer_address"]; present {
			signer, ok := raw.(string)
			if !ok || signer == "" {
				signer = "invalid"
			}
			info.Signer = signer
		}
		if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
			info.IssuedAt = iat.Time
		}
		return info, nil
	}
}
