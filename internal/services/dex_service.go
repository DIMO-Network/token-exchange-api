package services

import (
	"context"
	"fmt"
	"math/big"

	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	dgrpc "github.com/dexidp/dex/api/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:generate go tool mockgen -source dex_service.go -destination mocks/dex_service_mock.go
type DexService interface {
	SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error)
}

type DexClient struct {
	log    *zerolog.Logger
	client dgrpc.DexClient
}

type PrivilegeTokenDTO struct {
	UserEthAddress     string
	TokenID            *big.Int
	PrivilegeIDs       []int64
	ChainID            uint64
	NFTContractAddress common.Address
	Audience           []string
	CloudEvents        *tokenclaims.CloudEvents
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
	if req.TokenID == nil {
		return "", fmt.Errorf("token ID is required")
	}
	if req.NFTContractAddress == (common.Address{}) {
		return "", fmt.Errorf("NFT contract address is required")
	}
	if req.ChainID == 0 {
		return "", fmt.Errorf("chain ID is required")
	}

	privs := make([]privileges.Privilege, len(req.PrivilegeIDs))
	for i, iD := range req.PrivilegeIDs {
		privs[i] = privileges.Privilege(iD)
	}

	cc := tokenclaims.CustomClaims{
		ChainID:         req.ChainID,
		ContractAddress: req.NFTContractAddress,
		TokenID:         req.TokenID,
		PrivilegeIDs:    privs,
		CloudEvents:     req.CloudEvents,
	}

	ps, err := cc.Proto()
	if err != nil {
		return "", fmt.Errorf("failed to convert custom claims to .Proto(): %w", err)
	}

	args := &dgrpc.SignTokenReq{
		Subject:      "", // TODO: Merge with dev_license
		CustomClaims: ps,
		Audience:     req.Audience,
	}

	resp, err := d.client.SignToken(ctx, args)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return resp.Token, nil
}
