package sacdproxy

import (
	"context"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	vehicleContract = common.HexToAddress("0x1111111111111111111111111111111111111111")
	granteeAddr     = common.HexToAddress("0x3333333333333333333333333333333333333333")
	ownerAddr       = common.HexToAddress("0x4444444444444444444444444444444444444444")
)

func TestConvertTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID *big.Int
		want    int
		wantErr string
	}{
		{"nil pointer", nil, 0, "nil pointer"},
		{"zero value", big.NewInt(0), 0, "value not positive"},
		{"negative value", big.NewInt(-1), 0, "value not positive"},
		{"valid small value", big.NewInt(123), 123, ""},
		{"max int32", big.NewInt(math.MaxInt32), math.MaxInt32, ""},
		{"exceeds int32", big.NewInt(math.MaxInt32 + 1), 0, "outside of int32 range"},
		{"exceeds int64", new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1)), 0, "outside of int64 range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertTokenID(tt.tokenID)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProxy_GetPermissions(t *testing.T) {
	tests := []struct {
		name           string
		response       any
		statusCode     int
		tokenID        *big.Int
		requestedPerms *big.Int
		wantPerms      *big.Int
		wantErr        string
	}{
		{
			name: "vehicle with SACD returns intersection",
			response: graphQLResponse(ownerAddr, &sacdResponse{
				Permissions: "0xff",
				ExpiresAt:   time.Now().Add(time.Hour),
			}),
			tokenID:        big.NewInt(123),
			requestedPerms: big.NewInt(0x0f),
			wantPerms:      big.NewInt(0x0f), // 0xff AND 0x0f
		},
		{
			name:           "owner gets all requested permissions",
			response:       graphQLResponse(granteeAddr, nil), // grantee is owner
			tokenID:        big.NewInt(123),
			requestedPerms: big.NewInt(0xff),
			wantPerms:      big.NewInt(0xff),
		},
		{
			name:           "no SACD returns zero",
			response:       graphQLResponse(ownerAddr, nil),
			tokenID:        big.NewInt(123),
			requestedPerms: big.NewInt(0xff),
			wantPerms:      big.NewInt(0),
		},
		{
			name:           "vehicle not found returns zero",
			response:       map[string]any{"data": nil},
			tokenID:        big.NewInt(123),
			requestedPerms: big.NewInt(0xff),
			wantPerms:      big.NewInt(0),
		},
		{
			name:           "server error",
			statusCode:     http.StatusInternalServerError,
			tokenID:        big.NewInt(123),
			requestedPerms: big.NewInt(0xff),
			wantErr:        "unexpected status code 500",
		},
		{
			name:           "invalid token ID",
			tokenID:        big.NewInt(-1),
			requestedPerms: big.NewInt(0xff),
			wantErr:        "value not positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != 0 {
					w.WriteHeader(tt.statusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			proxy := &Proxy{
				HTTP:                   server.Client(),
				QueryEndpoint:          server.URL,
				ContractAddressVehicle: vehicleContract,
			}

			got, err := proxy.GetPermissions(
				&bind.CallOpts{Context: context.Background()},
				vehicleContract, tt.tokenID, granteeAddr, tt.requestedPerms,
			)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPerms, got)
		})
	}
}

func TestProxy_CurrentPermissionRecord(t *testing.T) {
	expiresAt := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		response   any
		wantPerms  *big.Int
		wantExpire *big.Int
		wantSource string
		wantTplID  *big.Int
		wantErr    string
	}{
		{
			name: "full SACD with template",
			response: graphQLResponse(ownerAddr, &sacdResponse{
				Permissions: "0xabcd",
				Source:      "ipfs://test",
				ExpiresAt:   expiresAt,
				TemplateID:  intPtr(99),
			}),
			wantPerms:  big.NewInt(0xabcd),
			wantExpire: big.NewInt(expiresAt.Unix()),
			wantSource: "ipfs://test",
			wantTplID:  big.NewInt(99),
		},
		{
			name: "SACD without template",
			response: graphQLResponse(ownerAddr, &sacdResponse{
				Permissions: "0x1234",
				Source:      "ipfs://notemplate",
				ExpiresAt:   expiresAt,
			}),
			wantPerms:  big.NewInt(0x1234),
			wantExpire: big.NewInt(expiresAt.Unix()),
			wantSource: "ipfs://notemplate",
			wantTplID:  big.NewInt(0),
		},
		{
			name:       "no SACD returns blank",
			response:   graphQLResponse(ownerAddr, nil),
			wantPerms:  big.NewInt(0),
			wantExpire: big.NewInt(0),
			wantTplID:  big.NewInt(0),
		},
		{
			name:       "vehicle not found returns blank",
			response:   map[string]any{"data": nil},
			wantPerms:  big.NewInt(0),
			wantExpire: big.NewInt(0),
			wantTplID:  big.NewInt(0),
		},
		{
			name: "invalid permissions hex",
			response: graphQLResponse(ownerAddr, &sacdResponse{
				Permissions: "not-hex",
				ExpiresAt:   expiresAt,
			}),
			wantErr: "couldn't parse permissions hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			proxy := &Proxy{
				HTTP:                   server.Client(),
				QueryEndpoint:          server.URL,
				ContractAddressVehicle: vehicleContract,
			}

			got, err := proxy.CurrentPermissionRecord(
				&bind.CallOpts{Context: context.Background()},
				vehicleContract, big.NewInt(123), granteeAddr,
			)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPerms, got.Permissions)
			assert.Equal(t, tt.wantExpire, got.Expiration)
			assert.Equal(t, tt.wantSource, got.Source)
			assert.Equal(t, tt.wantTplID, got.TemplateId)
		})
	}
}

// Helper types and functions for building test responses

type sacdResponse struct {
	Permissions string
	Source      string
	ExpiresAt   time.Time
	TemplateID  *int
}

func graphQLResponse(owner common.Address, sacd *sacdResponse) map[string]any {
	vehicle := map[string]any{"owner": owner.Hex()}

	if sacd != nil {
		s := map[string]any{
			"permissions": sacd.Permissions,
			"source":      sacd.Source,
			"expiresAt":   sacd.ExpiresAt.Format(time.RFC3339),
		}
		if sacd.TemplateID != nil {
			s["template"] = map[string]any{"tokenId": *sacd.TemplateID}
		}
		vehicle["sacd"] = s
	}

	return map[string]any{"data": map[string]any{"vehicle": vehicle}}
}

func intPtr(i int) *int { return &i }
