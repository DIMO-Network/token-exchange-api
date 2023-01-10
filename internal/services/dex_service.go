package services

import (
	"context"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	dgrpc "github.com/dexidp/dex/api/v2"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type DexService interface {
	SignPrivilegePayload(ctx context.Context, req DevicePrivilegeDTO) (string, error)
}

type dexService struct {
	log         *zerolog.Logger
	dexGRPCAddr string
}

type DevicePrivilegeDTO struct {
	UserEthAddress string
	DeviceTokenID  string
	PrivilegeIDs   []int64
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

func (d *dexService) SignPrivilegePayload(ctx context.Context, req DevicePrivilegeDTO) (string, error) {
	client, conn, err := d.getDexGrpcConnection()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	args := &dgrpc.GetPrivilegeTokenReq{
		UserEthAddress: req.UserEthAddress,
		DeviceTokenId:  req.DeviceTokenID,
		PrivilegeIds:   req.PrivilegeIDs,
	}

	resp, err := client.GetPrivilegeToken(ctx, args)
	if err != nil {
		return "", err
	}

	return resp.Token, nil
}
