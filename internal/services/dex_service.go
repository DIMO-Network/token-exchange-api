package services

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services/access"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	dgrpc "github.com/dexidp/dex/api/v2"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type DexClient struct {
	log    *zerolog.Logger
	client dgrpc.DexClient
}

type PrivilegeTokenDTO struct {
	*access.NFTAccessRequest
	Audience        []string
	ResponseSubject string
}

func NewDexClient(log *zerolog.Logger, dexgRPCAddr string) (*DexClient, error) {
	conn, err := grpc.NewClient(dexgRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create dex gRPC client: %w", err)
	}

	return &DexClient{
		log:    log,
		client: dgrpc.NewDexClient(conn),
	}, nil
}

func (d *DexClient) SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error) {
	privs := make([]privileges.Privilege, len(req.Permissions))
	for i, perm := range req.Permissions {
		permID, ok := models.PrivilegeNameToID[perm]
		if ok {
			privs[i] = privileges.Privilege(permID)
		}
	}
	events := make([]tokenclaims.Event, len(req.EventFilters))
	for i, event := range req.EventFilters {
		events[i] = tokenclaims.Event{
			EventType: event.EventType,
			Source:    event.Source,
			IDs:       event.IDs,
			Tags:      event.Tags,
		}
	}

	cc := tokenclaims.CustomClaims{
		Asset:       req.Asset.String(),
		Permissions: req.Permissions,
		CloudEvents: &tokenclaims.CloudEvents{Events: events},

		// Old fields
		ContractAddress: req.Asset.ContractAddress,
		TokenID:         req.Asset.TokenID.String(),
		PrivilegeIDs:    privs,
	}

	ps, err := cc.Proto()
	if err != nil {
		return "", fmt.Errorf("failed to convert custom claims to .Proto(): %w", err)
	}

	args := &dgrpc.SignTokenReq{
		Subject:      req.ResponseSubject,
		CustomClaims: ps,
		Audience:     req.Audience,
	}

	resp, err := d.client.SignToken(ctx, args)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return resp.Token, nil
}
