// Package rpc implements the gRPC server for the token exchange service.
package rpc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services/access"
	"github.com/DIMO-Network/token-exchange-api/pkg/grpc"
	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SignerChecker answers whether a signer may still act for a license.
type SignerChecker interface {
	Check(ctx context.Context, license, signer common.Address) (signercheck.Result, error)
}

// TokenExchangeServer represents the gRPC server
type TokenExchangeServer struct {
	grpc.UnimplementedTokenExchangeServiceServer
	accessService *access.Service
	signerChecker SignerChecker
}

// NewTokenExchangeServer creates a new TokenExchangeServer.
func NewTokenExchangeServer(accessService *access.Service, signerChecker SignerChecker) *TokenExchangeServer {
	return &TokenExchangeServer{
		accessService: accessService,
		signerChecker: signerChecker,
	}
}

// AccessCheck checks if the grantee has access to the asset.
func (s *TokenExchangeServer) AccessCheck(ctx context.Context, req *grpc.AccessCheckRequest) (*grpc.AccessCheckResponse, error) {
	assetDID, err := models.DecodeAssetDID(req.GetAsset())
	if err != nil {
		return nil, fmt.Errorf("failed to decode asset DID: %w", err)
	}

	events := make([]models.EventFilter, len(req.GetEvents()))
	for i, event := range req.GetEvents() {
		events[i] = models.EventFilter{
			EventType: event.GetEventType(),
			Source:    event.GetSource(),
			IDs:       event.GetIds(),
		}
	}

	accessReq := &access.AccessRequest{
		Asset:        assetDID,
		Permissions:  req.GetPrivileges(),
		EventFilters: events,
	}
	if req.GetGrantee() == "" {
		return nil, fmt.Errorf("grantee is required")
	}
	err = s.accessService.ValidateAccess(ctx, accessReq, common.HexToAddress(req.GetGrantee()))
	if err != nil {
		richErr, ok := richerrors.AsRichError(err)
		if !ok {
			richErr = richerrors.Error{
				Code: http.StatusInternalServerError,
				Err:  err,
			}
		}
		return &grpc.AccessCheckResponse{
			HasAccess: false,
			Reason:    err.Error(),
			RichError: &grpc.RichError{
				Code:        int32(richErr.Code),
				ExternalMsg: richErr.ExternalMsg,
				Err:         fmt.Sprintf("%v", richErr.Err),
			},
		}, nil
	}

	return &grpc.AccessCheckResponse{
		HasAccess: true,
	}, nil
}

// SignerCheck reports whether a developer JWT's signer may still act for its license. It
// answers true for addresses that aren't developer licenses, and shares the HTTP path's
// 60-second cache.
func (s *TokenExchangeServer) SignerCheck(ctx context.Context, req *grpc.SignerCheckRequest) (*grpc.SignerCheckResponse, error) {
	if !common.IsHexAddress(req.GetLicense()) || !common.IsHexAddress(req.GetSigner()) {
		return nil, status.Error(codes.InvalidArgument, "license and signer must be hex addresses")
	}
	result, err := s.signerChecker.Check(ctx, common.HexToAddress(req.GetLicense()), common.HexToAddress(req.GetSigner()))
	if err != nil {
		return nil, status.Error(codes.Unavailable, signercheck.MessageUnavailable)
	}
	return &grpc.SignerCheckResponse{IsSigner: result != signercheck.Denied}, nil
}
