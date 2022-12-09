package services

import (
	"context"

	pb "github.com/DIMO-Network/shared/api/users"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type UsersService interface {
	GetUserByID(ctx context.Context, userID string) (*pb.User, error)
}

type usersService struct {
	log           *zerolog.Logger
	usersGRPCAddr string
}

func NewUsersService(log *zerolog.Logger, settings *config.Settings) *usersService {
	return &usersService{
		log:           log,
		usersGRPCAddr: settings.UsersAPIGRPCAddress,
	}
}

func (u *usersService) getUsersServiceGrpcConnection() (pb.UserServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.Dial(u.usersGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, conn, err
	}
	client := pb.NewUserServiceClient(conn)
	return client, conn, nil
}

func (u *usersService) GetUserByID(ctx context.Context, userID string) (*pb.User, error) {
	client, conn, err := u.getUsersServiceGrpcConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return client.GetUser(ctx, &pb.GetUserRequest{
		Id: userID,
	})
}
