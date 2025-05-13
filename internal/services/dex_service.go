package services

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/shared/privileges"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	dgrpc "github.com/dexidp/dex/api/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:generate mockgen -source dex_service.go -destination mocks/dex_service_mock.go
type DexService interface {
	SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error)
}

type DexClient struct {
	log    *zerolog.Logger
	client dgrpc.DexClient
}

type PrivilegeTokenDTO struct {
	UserEthAddress     string
	TokenID            string
	PrivilegeIDs       []int64
	NFTContractAddress string
	Audience           []string
}

func NewDexClient(log *zerolog.Logger, dexgRPCAddr string) (*DexClient, error) {
	conn, err := grpc.NewClient(dexgRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dex gRPC server: %w", err)
	}

	return &DexClient{
		log:    log,
		client: dgrpc.NewDexClient(conn),
	}, nil
}

func (d *DexClient) SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error) {
	privs := make([]privileges.Privilege, len(req.PrivilegeIDs))
	for i, iD := range req.PrivilegeIDs {
		privs[i] = privileges.Privilege(iD)
	}

	cc := tokenclaims.CustomClaims{
		ContractAddress: common.HexToAddress(req.NFTContractAddress),
		TokenID:         req.TokenID,
		PrivilegeIDs:    privs,
	}

	ps, err := cc.Proto()
	if err != nil {
		return "", fmt.Errorf("failed to convert custom claims to .Proto(): %w", err)
	}

	args := &dgrpc.SignTokenReq{
		Subject:      cc.Sub(),
		CustomClaims: ps,
		Audience:     req.Audience,
	}

	resp, err := d.client.SignToken(ctx, args)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return resp.Token, nil
}
