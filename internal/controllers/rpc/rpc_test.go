package rpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DIMO-Network/token-exchange-api/internal/controllers/rpc"
	"github.com/DIMO-Network/token-exchange-api/pkg/grpc"
	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:generate go tool mockgen -source ./rpc.go -destination ./rpc_mock_test.go -package rpc_test

func TestSignerCheck(t *testing.T) {
	license := common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	signer := common.HexToAddress("0x71efD5d71a597eB6BEC28DFDB05a49283a3e20c5")
	request := &grpc.SignerCheckRequest{License: license.Hex(), Signer: signer.Hex()}

	for name, tc := range map[string]struct {
		result signercheck.Result
		want   bool
	}{
		"enabled signer answers true":   {result: signercheck.Allowed, want: true},
		"disabled signer answers false": {result: signercheck.Denied, want: false},
		"non-license answers true":      {result: signercheck.NotLicense, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			checker := NewMockSignerChecker(gomock.NewController(t))
			checker.EXPECT().Check(gomock.Any(), license, signer).Return(tc.result, nil)

			resp, err := rpc.NewTokenExchangeServer(nil, checker).SignerCheck(context.Background(), request)

			require.NoError(t, err)
			require.Equal(t, tc.want, resp.GetIsSigner())
		})
	}

	t.Run("rejects addresses that are not hex", func(t *testing.T) {
		checker := NewMockSignerChecker(gomock.NewController(t))

		_, err := rpc.NewTokenExchangeServer(nil, checker).SignerCheck(context.Background(), &grpc.SignerCheckRequest{
			License: "not-an-address",
			Signer:  signer.Hex(),
		})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("checker errors are Unavailable", func(t *testing.T) {
		checker := NewMockSignerChecker(gomock.NewController(t))
		checker.EXPECT().Check(gomock.Any(), license, signer).Return(signercheck.Denied, errors.New("rpc down"))

		_, err := rpc.NewTokenExchangeServer(nil, checker).SignerCheck(context.Background(), request)

		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Equal(t, signercheck.MessageUnavailable, status.Convert(err).Message())
	})
}
