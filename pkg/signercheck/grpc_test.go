package signercheck

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	txgrpc "github.com/DIMO-Network/token-exchange-api/pkg/grpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type signerCheckServer struct {
	txgrpc.UnimplementedTokenExchangeServiceServer
	got   *txgrpc.SignerCheckRequest
	resp  *txgrpc.SignerCheckResponse
	err   error
	delay time.Duration
}

func (s *signerCheckServer) SignerCheck(ctx context.Context, req *txgrpc.SignerCheckRequest) (*txgrpc.SignerCheckResponse, error) {
	s.got = req
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.resp, s.err
}

func newBufconnChecker(t *testing.T, srv txgrpc.TokenExchangeServiceServer) *GRPCChecker {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	txgrpc.RegisterTokenExchangeServiceServer(server, srv)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return NewGRPCChecker(txgrpc.NewTokenExchangeServiceClient(conn))
}

func TestGRPCChecker(t *testing.T) {
	for isSigner, want := range map[bool]Result{true: Allowed, false: Denied} {
		srv := &signerCheckServer{resp: &txgrpc.SignerCheckResponse{IsSigner: isSigner}}

		got, err := newBufconnChecker(t, srv).Check(context.Background(), testLicense, testSigner)

		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, testLicense.Hex(), srv.got.GetLicense())
		require.Equal(t, testSigner.Hex(), srv.got.GetSigner())
	}

	_, err := newBufconnChecker(t, &signerCheckServer{err: status.Error(codes.Unavailable, MessageUnavailable)}).
		Check(context.Background(), testLicense, testSigner)
	require.ErrorContains(t, err, MessageUnavailable)
}

func TestGRPCCheckerTimesOut(t *testing.T) {
	checker := newBufconnChecker(t, &signerCheckServer{delay: time.Minute, resp: &txgrpc.SignerCheckResponse{IsSigner: true}})
	checker.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err := checker.Check(context.Background(), testLicense, testSigner)

	require.Error(t, err)
	require.Equal(t, codes.DeadlineExceeded, status.Code(errors.Unwrap(err)))
	require.Less(t, time.Since(start), 2*time.Second)
}
