package services

import (
	"context"

	pi "github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	dgrpc "github.com/dexidp/dex/api/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type DexService interface {
	SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error)
}

type dexService struct {
	log         *zerolog.Logger
	dexGRPCAddr string
}

type PrivilegeTokenDTO struct {
	UserEthAddress     string
	TokenID            string
	PrivilegeIDs       []int64
	NFTContractAddress string
}

func NewDexService(log *zerolog.Logger, settings *config.Settings) *dexService {
	return &dexService{
		log:         log,
		dexGRPCAddr: settings.DexGRPCAdddress,
	}
}

func (d *dexService) getDexGrpcConnection() (dgrpc.DexClient, *grpc.ClientConn, error) {
	conn, err := grpc.Dial(d.dexGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, conn, err
	}
	dexClient := dgrpc.NewDexClient(conn)
	return dexClient, conn, nil
}

func (d *dexService) SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error) {
	client, conn, err := d.getDexGrpcConnection()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	cc := pi.CustomClaims{
		ContractAddress: common.HexToAddress(req.NFTContractAddress),
		TokenID:         req.TokenID,
		PrivilegeIDs:    req.PrivilegeIDs,
	}

	ps, err := cc.Proto()
	if err != nil {
		return "", err
	}

	args := &dgrpc.SignTokenReq{
		Subject:      cc.Sub(),
		CustomClaims: ps,
	}

	resp, err := client.SignToken(ctx, args)
	if err != nil {
		return "", err
	}

	return resp.Token, nil
}
