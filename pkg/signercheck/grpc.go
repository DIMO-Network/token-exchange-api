package signercheck

import (
	"context"
	"fmt"
	"time"

	txgrpc "github.com/DIMO-Network/token-exchange-api/pkg/grpc"
	"github.com/ethereum/go-ethereum/common"
)

// GRPCTimeout bounds one SignerCheck call.
const GRPCTimeout = 5 * time.Second

// GRPCChecker checks signers through token-exchange-api's SignerCheck gRPC, which shares
// token-exchange-api's 60-second cache. Every gRPC error, the deadline included, is an
// error, so Middleware answers 503 in enforce mode.
type GRPCChecker struct {
	client  txgrpc.TokenExchangeServiceClient
	timeout time.Duration
}

// NewGRPCChecker returns a Checker backed by SignerCheck with a 5-second deadline.
func NewGRPCChecker(client txgrpc.TokenExchangeServiceClient) *GRPCChecker {
	return &GRPCChecker{client: client, timeout: GRPCTimeout}
}

// Check implements Checker. token-exchange-api answers true for an address that isn't a
// developer license, so callers see Allowed there.
func (g *GRPCChecker) Check(ctx context.Context, license, signer common.Address) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	resp, err := g.client.SignerCheck(ctx, &txgrpc.SignerCheckRequest{License: license.Hex(), Signer: signer.Hex()})
	if err != nil {
		return Denied, fmt.Errorf("signer check for license %s: %w", license.Hex(), err)
	}
	if resp.GetIsSigner() {
		return Allowed, nil
	}
	return Denied, nil
}
