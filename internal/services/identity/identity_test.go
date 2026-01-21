package identity

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_GetVehicleSACDSource(t *testing.T) {
	grantee := common.HexToAddress("0x1234567890123456789012345678901234567890")
	owner := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")

	tests := []struct {
		name           string
		tokenID        int
		grantee        common.Address
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectedSource string
		expectError    bool
		errorContains  string
	}{
		{
			name:    "success with valid SACD",
			tokenID: 123,
			grantee: grantee,
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD: &sacd{
								Permissions: "0x1234",
								Source:      "ipfs://QmTest123",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectedSource: "ipfs://QmTest123",
		},
		{
			name:    "no SACD for grantee",
			tokenID: 123,
			grantee: grantee,
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD:  nil,
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "no SACD",
		},
		{
			name:    "vehicle not found",
			tokenID: 999,
			grantee: grantee,
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: nil,
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "vehicle not found",
		},
		{
			name:    "server returns non-200 status",
			tokenID: 123,
			grantee: grantee,
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectError:   true,
			errorContains: "status code 500",
		},
		{
			name:    "server returns invalid JSON",
			tokenID: 123,
			grantee: grantee,
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("not json"))
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tc.serverResponse))
			defer server.Close()

			client := &Client{
				HTTP:          server.Client(),
				QueryEndpoint: server.URL,
			}

			source, err := client.GetVehicleSACDSource(context.Background(), tc.tokenID, tc.grantee)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectedSource, source)
		})
	}
}

func TestClient_GetVehicleSACDPermissions(t *testing.T) {
	grantee := common.HexToAddress("0x1234567890123456789012345678901234567890")
	owner := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")

	tests := []struct {
		name                string
		tokenID             int
		grantee             common.Address
		requestedPerms      *big.Int
		serverResponse      func(w http.ResponseWriter, r *http.Request)
		expectedPermissions *big.Int
		expectError         bool
		errorContains       string
	}{
		{
			name:           "grantee is owner - returns all requested permissions",
			tokenID:        123,
			grantee:        owner,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD:  nil, // Owner doesn't need SACD
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectedPermissions: big.NewInt(0b111100),
		},
		{
			name:           "grantee has SACD with full permissions",
			tokenID:        123,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD: &sacd{
								Permissions: "0x3c", // 0b111100
								Source:      "ipfs://test",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectedPermissions: big.NewInt(0b111100),
		},
		{
			name:           "grantee has SACD with partial permissions - returns intersection",
			tokenID:        123,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD: &sacd{
								Permissions: "0xc", // 0b001100 - format matches "0x" + big.Int.Text(16)
								Source:      "ipfs://test",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectedPermissions: big.NewInt(0b001100), // intersection of 0b111100 and 0b001100
		},
		{
			name:           "grantee has no matching permissions",
			tokenID:        123,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD: &sacd{
								Permissions: "0x3", // 0b000011 - format matches "0x" + big.Int.Text(16)
								Source:      "ipfs://test",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectedPermissions: big.NewInt(0), // no overlap
		},
		{
			name:           "no SACD for non-owner grantee",
			tokenID:        123,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD:  nil,
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "no SACD",
		},
		{
			name:           "vehicle not found",
			tokenID:        999,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: nil,
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "vehicle not found",
		},
		{
			name:           "invalid permissions hex in response",
			tokenID:        123,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{
					Data: &struct {
						Vehicle *vehicle `json:"vehicle"`
					}{
						Vehicle: &vehicle{
							Owner: owner,
							SACD: &sacd{
								Permissions: "not-a-hex",
								Source:      "ipfs://test",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectError: true,
		},
		{
			name:           "server error",
			tokenID:        123,
			grantee:        grantee,
			requestedPerms: big.NewInt(0b111100),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectError:   true,
			errorContains: "status code 500",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tc.serverResponse))
			defer server.Close()

			client := &Client{
				HTTP:          server.Client(),
				QueryEndpoint: server.URL,
			}

			perms, err := client.GetVehicleSACDPermissions(context.Background(), tc.tokenID, tc.grantee, tc.requestedPerms)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, 0, tc.expectedPermissions.Cmp(perms), "expected %s, got %s", tc.expectedPermissions.String(), perms.String())
		})
	}
}

func TestClient_GetVehicleSACD_RequestFormat(t *testing.T) {
	grantee := common.HexToAddress("0x1234567890123456789012345678901234567890")
	owner := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")

	var receivedRequest queryRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Parse and store the request
		json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Return a valid response
		resp := queryResponse{
			Data: &struct {
				Vehicle *vehicle `json:"vehicle"`
			}{
				Vehicle: &vehicle{
					Owner: owner,
					SACD: &sacd{
						Permissions: "0x1234",
						Source:      "ipfs://test",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &Client{
		HTTP:          server.Client(),
		QueryEndpoint: server.URL,
	}

	_, err := client.GetVehicleSACDSource(context.Background(), 456, grantee)
	require.NoError(t, err)

	// Verify the GraphQL query format
	assert.Contains(t, receivedRequest.Query, "vehicle(tokenId: $tokenId)")
	assert.Contains(t, receivedRequest.Query, "sacd(grantee: $grantee)")
	// JSON unmarshals numbers as float64 and addresses as strings
	assert.Equal(t, float64(456), receivedRequest.Variables["tokenId"])
	assert.Equal(t, grantee.Hex(), receivedRequest.Variables["grantee"])
}
