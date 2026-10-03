package licensesigner

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// fakeCaller answers isSigner calls from a queue (the last answer repeats). With block set,
// each call waits for release to close or its context to end.
type fakeCaller struct {
	mu      sync.Mutex
	answers []fakeAnswer
	calls   []ethereum.CallMsg
	block   bool
	release chan struct{}
}

type fakeAnswer struct {
	isSigner bool
	err      error
}

func (f *fakeCaller) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return []byte{0x60}, nil
}

func (f *fakeCaller) CallContract(ctx context.Context, call ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	f.mu.Lock()
	answer := f.answers[min(len(f.calls), len(f.answers)-1)]
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	if f.block {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if answer.err != nil {
		return nil, answer.err
	}
	out := make([]byte, 32)
	if answer.isSigner {
		out[31] = 1
	}
	return out, nil
}

func (f *fakeCaller) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeLicenses answers IsDevLicense with isLicense or err and counts lookups.
type fakeLicenses struct {
	mu        sync.Mutex
	isLicense bool
	err       error
	lookups   int
}

func (f *fakeLicenses) IsDevLicense(context.Context, common.Address) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	return f.isLicense, f.err
}

var (
	license = common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	signer  = common.HexToAddress("0x71efD5d71a597eB6BEC28DFDB05a49283a3e20c5")
)

func newTestChecker(caller *fakeCaller, licenses *fakeLicenses, now *time.Time) *Checker {
	checker := NewChecker(caller, licenses)
	checker.now = func() time.Time { return *now }
	return checker
}

func TestCheckerCallsIsSignerOnTheLicenseAccount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	caller := &fakeCaller{answers: []fakeAnswer{{isSigner: true}}}

	got, err := newTestChecker(caller, &fakeLicenses{isLicense: true}, &now).Check(context.Background(), license, signer)

	require.NoError(t, err)
	require.Equal(t, signercheck.Allowed, got)
	require.Len(t, caller.calls, 1)
	call := caller.calls[0]
	require.Equal(t, license, *call.To)
	require.Equal(t, crypto.Keccak256([]byte("isSigner(address)"))[:4], call.Data[:4])
	require.Equal(t, signer, common.BytesToAddress(call.Data[4:36]))
}

func TestCheckerCachesBothAnswersForTTL(t *testing.T) {
	for _, isSigner := range []bool{true, false} {
		now := time.Unix(1_700_000_000, 0)
		caller := &fakeCaller{answers: []fakeAnswer{{isSigner: isSigner}, {isSigner: !isSigner}}}
		checker := newTestChecker(caller, &fakeLicenses{isLicense: true}, &now)
		want := map[bool]signercheck.Result{true: signercheck.Allowed, false: signercheck.Denied}

		got, err := checker.Check(context.Background(), license, signer)
		require.NoError(t, err)
		require.Equal(t, want[isSigner], got)

		now = now.Add(TTL - time.Second)
		got, err = checker.Check(context.Background(), license, signer)
		require.NoError(t, err)
		require.Equal(t, want[isSigner], got, "an answer within the TTL comes from the cache")
		require.Equal(t, 1, caller.callCount())

		now = now.Add(time.Second)
		got, err = checker.Check(context.Background(), license, signer)
		require.NoError(t, err)
		require.Equal(t, want[!isSigner], got, "at the TTL the chain is asked again")
		require.Equal(t, 2, caller.callCount())
	}
}

func TestCheckerNotLicenseSkipsTheChain(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	caller := &fakeCaller{answers: []fakeAnswer{{isSigner: false}}}
	licenses := &fakeLicenses{isLicense: false}
	checker := newTestChecker(caller, licenses, &now)

	for range 2 {
		got, err := checker.Check(context.Background(), license, signer)
		require.NoError(t, err)
		require.Equal(t, signercheck.NotLicense, got)
	}
	require.Equal(t, 0, caller.callCount())
	require.Equal(t, 1, licenses.lookups, "the not-a-license answer is cached too")
}

func TestCheckerDoesNotCacheErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	caller := &fakeCaller{answers: []fakeAnswer{{err: errors.New("rpc down")}, {isSigner: true}}}
	checker := newTestChecker(caller, &fakeLicenses{isLicense: true}, &now)

	_, err := checker.Check(context.Background(), license, signer)
	require.ErrorContains(t, err, "rpc down")

	got, err := checker.Check(context.Background(), license, signer)
	require.NoError(t, err)
	require.Equal(t, signercheck.Allowed, got)
	require.Equal(t, 2, caller.callCount())

	licenses := &fakeLicenses{err: errors.New("identity down")}
	_, err = newTestChecker(caller, licenses, &now).Check(context.Background(), license, signer)
	require.ErrorContains(t, err, "identity down")
}

func TestCheckerKeysByLicenseAndSigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	caller := &fakeCaller{answers: []fakeAnswer{{isSigner: true}, {isSigner: false}}}
	checker := newTestChecker(caller, &fakeLicenses{isLicense: true}, &now)
	other := common.HexToAddress("0x955029AC2539f4D57A1D7E6Ef2b97617e95Eb1D4")

	got, err := checker.Check(context.Background(), license, signer)
	require.NoError(t, err)
	require.Equal(t, signercheck.Allowed, got)

	got, err = checker.Check(context.Background(), license, other)
	require.NoError(t, err)
	require.Equal(t, signercheck.Denied, got)
	require.Equal(t, 2, caller.callCount())
}

func TestCheckerBoundsTheCache(t *testing.T) {
	previous := maxEntries
	maxEntries = 2
	t.Cleanup(func() { maxEntries = previous })

	now := time.Unix(1_700_000_000, 0)
	checker := newTestChecker(&fakeCaller{answers: []fakeAnswer{{isSigner: true}}}, &fakeLicenses{isLicense: true}, &now)

	for i := range 3 {
		_, err := checker.Check(context.Background(), license, common.BigToAddress(big.NewInt(int64(i+1))))
		require.NoError(t, err)
	}
	require.LessOrEqual(t, len(checker.results), 2)
}

func TestCheckerTimesOut(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	caller := &fakeCaller{answers: []fakeAnswer{{isSigner: true}}, block: true, release: make(chan struct{})}
	checker := newTestChecker(caller, &fakeLicenses{isLicense: true}, &now)
	checker.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err := checker.Check(context.Background(), license, signer)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestCheckerSharesConcurrentMisses(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	caller := &fakeCaller{answers: []fakeAnswer{{isSigner: true}}, block: true, release: make(chan struct{})}
	checker := newTestChecker(caller, &fakeLicenses{isLicense: true}, &now)

	var wg sync.WaitGroup
	results := make([]signercheck.Result, 10)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := checker.Check(context.Background(), license, signer)
			if err != nil {
				t.Error(err) // not require: FailNow must not run off the test goroutine
			}
			results[i] = got
		}()
	}
	require.Eventually(t, func() bool { return caller.callCount() == 1 }, time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // let the other goroutines join the in-flight call
	close(caller.release)
	wg.Wait()

	require.Equal(t, 1, caller.callCount())
	for _, got := range results {
		require.Equal(t, signercheck.Allowed, got)
	}
}
