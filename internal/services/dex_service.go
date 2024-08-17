package services

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
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

type dexService struct {
	log    *zerolog.Logger
	client dgrpc.DexClient
}

type PrivilegeTokenDTO struct {
	TokenID            string
	PrivilegeIDs       []int64
	NFTContractAddress common.Address
	Audience           []string
}

func NewDexService(log *zerolog.Logger, dexAddr string) (DexService, error) {
	conn, err := grpc.Dial(dexAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	dexClient := dgrpc.NewDexClient(conn)
	return &dexService{
		log:    log,
		client: dexClient,
	}, nil
}

func (d *dexService) SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error) {
	privs := make([]privileges.Privilege, len(req.PrivilegeIDs))
	for i, iD := range req.PrivilegeIDs {
		privs[i] = privileges.Privilege(iD)
	}

	cc := privilegetoken.CustomClaims{
		ContractAddress: req.NFTContractAddress,
		TokenID:         req.TokenID,
		PrivilegeIDs:    privs,
	}

	ps, err := cc.Proto()
	if err != nil {
		return "", fmt.Errorf("couldn't construct custom claims: %w", err)
	}

	args := &dgrpc.SignTokenReq{
		Subject:      cc.Sub(),
		CustomClaims: ps,
		Audience:     req.Audience,
	}

	resp, err := d.client.SignToken(ctx, args)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	return resp.Token, nil
}
