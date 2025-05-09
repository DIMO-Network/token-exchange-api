package services

import (
	"context"

	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	dgrpc "github.com/dexidp/dex/api/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:generate mockgen -source dex_service.go -destination mocks/dex_service_mock.go
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
	Audience           []string
	Attestations       []Attestation
}

type Attestation struct {
	EventType      string   `json:"eventType"`
	Source         *string  `json:"source"`
	AttestationIDs []string `json:"id"`
}

func NewDexService(log *zerolog.Logger, settings *config.Settings) DexService {
	return &dexService{
		log:         log,
		dexGRPCAddr: settings.DexGRPCAdddress,
	}
}

func (d *dexService) getDexGrpcConnection() (dgrpc.DexClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(d.dexGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, conn, err
	}
	dexClient := dgrpc.NewDexClient(conn)
	return dexClient, conn, nil
}

func (d *dexService) SignPrivilegePayload(ctx context.Context, req PrivilegeTokenDTO) (string, error) {
	client, conn, err := d.getDexGrpcConnection()
	if err != nil {
		return "", errors.Wrap(err, "unable to get dex grpc connection")
	}
	defer conn.Close()
	privs := make([]privileges.Privilege, len(req.PrivilegeIDs))
	for i, iD := range req.PrivilegeIDs {
		privs[i] = privileges.Privilege(iD)
	}

	cc := privilegetoken.CustomClaims{
		ContractAddress: common.HexToAddress(req.NFTContractAddress),
		TokenID:         req.TokenID,
		PrivilegeIDs:    privs,
	}

	ps, err := cc.Proto()
	if err != nil {
		return "", errors.Wrap(err, "unable to convert custom claims to .Proto()")
	}

	args := &dgrpc.SignTokenReq{
		Subject:      cc.Sub(),
		CustomClaims: ps,
		Audience:     req.Audience,
	}

	resp, err := client.SignToken(ctx, args)
	if err != nil {
		return "", errors.Wrap(err, "unable to sign token")
	}

	return resp.Token, nil
}
