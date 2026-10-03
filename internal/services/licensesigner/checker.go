// Package licensesigner checks whether an address is still an enabled signer (API key) on a
// developer license. It is the only place that asks the chain; other services reach it
// through the SignerCheck gRPC.
package licensesigner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/DIMO-Network/token-exchange-api/internal/contracts/devlicenseaccount"
	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sync/singleflight"
)

// TTL is how long an answer is reused. Removing a console team member must end their access
// within about ten minutes, the lifetime of a vehicle JWT; this keeps the check's share of
// that to one minute.
const TTL = 60 * time.Second

// Timeout bounds each Identity lookup and each chain call.
const Timeout = 3 * time.Second

// maxEntries bounds each cache. When a write finds one full, expired answers are dropped,
// and if none are expired that cache starts over.
var maxEntries = 10_000

// LicenseLookup reports whether an address is a developer license's client ID.
type LicenseLookup interface {
	IsDevLicense(ctx context.Context, addr common.Address) (bool, error)
}

// Checker answers whether a signer may still act for a license. It reuses every answer,
// positive or negative, for TTL, never caches errors, and lets concurrent misses for the
// same key share one call.
type Checker struct {
	caller   bind.ContractCaller
	licenses LicenseLookup
	ttl      time.Duration
	timeout  time.Duration
	now      func() time.Time

	group singleflight.Group

	mu        sync.Mutex
	results   map[signerKey]resultEntry
	isLicense map[common.Address]licenseEntry
}

type signerKey struct {
	license common.Address
	signer  common.Address
}

type resultEntry struct {
	result  signercheck.Result
	expires time.Time
}

type licenseEntry struct {
	isLicense bool
	expires   time.Time
}

// NewChecker returns a Checker that calls isSigner on license accounts through caller and
// asks licenses whether an address is a license.
func NewChecker(caller bind.ContractCaller, licenses LicenseLookup) *Checker {
	return &Checker{
		caller:    caller,
		licenses:  licenses,
		ttl:       TTL,
		timeout:   Timeout,
		now:       time.Now,
		results:   make(map[signerKey]resultEntry),
		isLicense: make(map[common.Address]licenseEntry),
	}
}

// Check implements signercheck.Checker: NotLicense when license isn't a developer license,
// otherwise Allowed or Denied from isSigner on the license account.
func (c *Checker) Check(ctx context.Context, license, signer common.Address) (signercheck.Result, error) {
	key := signerKey{license: license, signer: signer}
	if result, ok := c.cachedResult(key); ok {
		return result, nil
	}
	v, err, _ := c.group.Do("signer:"+license.Hex()+":"+signer.Hex(), func() (any, error) {
		if result, ok := c.cachedResult(key); ok {
			return result, nil
		}
		isLicense, err := c.IsLicense(ctx, license)
		if err != nil {
			return nil, err
		}
		result := signercheck.NotLicense
		if isLicense {
			isSigner, err := c.isSigner(ctx, license, signer)
			if err != nil {
				return nil, err
			}
			result = signercheck.Denied
			if isSigner {
				result = signercheck.Allowed
			}
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.results) >= maxEntries {
			c.results = prune(c.results, c.now(), func(e resultEntry) time.Time { return e.expires })
		}
		c.results[key] = resultEntry{result: result, expires: c.now().Add(c.ttl)}
		return result, nil
	})
	if err != nil {
		return signercheck.Denied, err
	}
	return v.(signercheck.Result), nil
}

// IsLicense reports whether addr is a developer license, cached like Check.
func (c *Checker) IsLicense(ctx context.Context, addr common.Address) (bool, error) {
	c.mu.Lock()
	entry, ok := c.isLicense[addr]
	c.mu.Unlock()
	if ok && c.now().Before(entry.expires) {
		return entry.isLicense, nil
	}
	v, err, _ := c.group.Do("license:"+addr.Hex(), func() (any, error) {
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
		defer cancel()
		isLicense, err := c.licenses.IsDevLicense(callCtx, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to look up license %s: %w", addr.Hex(), err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.isLicense) >= maxEntries {
			c.isLicense = prune(c.isLicense, c.now(), func(e licenseEntry) time.Time { return e.expires })
		}
		c.isLicense[addr] = licenseEntry{isLicense: isLicense, expires: c.now().Add(c.ttl)}
		return isLicense, nil
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (c *Checker) cachedResult(key signerKey) (signercheck.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.results[key]
	if !ok || !c.now().Before(entry.expires) {
		return 0, false
	}
	return entry.result, true
}

// isSigner calls isSigner on the license account, detached from the request's cancellation
// (a shared call must not fail because its first caller went away) but bounded by c.timeout.
func (c *Checker) isSigner(ctx context.Context, license, signer common.Address) (bool, error) {
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	account, err := devlicenseaccount.NewDevLicenseAccountCaller(license, c.caller)
	if err != nil {
		return false, fmt.Errorf("failed to bind license account %s: %w", license.Hex(), err)
	}
	isSigner, err := account.IsSigner(&bind.CallOpts{Context: callCtx}, signer)
	if err != nil {
		return false, fmt.Errorf("failed to call isSigner on license account %s: %w", license.Hex(), err)
	}
	return isSigner, nil
}

// prune drops expired entries; if none were expired it starts over, so a cache never grows
// past maxEntries.
func prune[K comparable, V any](m map[K]V, now time.Time, expires func(V) time.Time) map[K]V {
	for k, v := range m {
		if !now.Before(expires(v)) {
			delete(m, k)
		}
	}
	if len(m) >= maxEntries {
		return make(map[K]V)
	}
	return m
}
