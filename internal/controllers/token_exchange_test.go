package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	mock_contracts "github.com/DIMO-Network/token-exchange-api/internal/contracts/mocks"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"

	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	mock_middleware "github.com/DIMO-Network/token-exchange-api/internal/middleware/mocks"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	mock_services "github.com/DIMO-Network/token-exchange-api/internal/services/mocks"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen -source ./token_exchange.go -destination ./token_exchange_mock_test.go -package controllers

func TestTokenExchangeController_GetDeviceCommandPermissionWithScope(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "token-exchange-api").
		Logger()

	dexService := mock_services.NewMockDexService(mockCtrl)
	contractsMgr := mock_contracts.NewMockManager(mockCtrl)
	mockMultiPriv := mock_contracts.NewMockMultiPriv(mockCtrl)
	mockSacd := mock_contracts.NewMockSacd(mockCtrl)
	mockipfs := NewMockIPFSService(mockCtrl)

	// This never gets called.
	client := ethclient.Client{}

	// setup app and route req
	c, err := NewTokenExchangeController(&logger, &config.Settings{
		BlockchainNodeURL:        "http://testurl.com/mock",
		ContractAddressWhitelist: "",
		ContractAddressSacd:      "0xa6",
	}, dexService, mockipfs, contractsMgr, &client)
	require.NoError(t, err, "Failed to initialize token exchange controller")

	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	// Create a mock empty permission record to return
	emptyPermRecord := sacd.ISacdPermissionRecord{
		Permissions: big.NewInt(0),
		Expiration:  big.NewInt(0),
		Source:      "",
	}

	tests := []struct {
		name                   string
		tokenClaims            jwt.MapClaims
		userEthAddr            *common.Address
		permissionTokenRequest *TokenRequest
		mockSetup              func()
		expectedCode           int
	}{
		{
			name: "auth jwt with ethereum addr",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				contractsMgr.EXPECT().GetSacd(c.settings.ContractAddressSacd, &client).Return(mockSacd, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{4},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           defaultAudience,
				}).Return("jwt", nil)
				mockSacd.EXPECT().CurrentPermissionRecord(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b1100000000)).Return(big.NewInt(0b1100000000), nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "eth token, multiple perms, success on SACD",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &TokenRequest{
				TokenID:            123,
				Privileges:         []int64{1, 2, 4, 5},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				contractsMgr.EXPECT().GetSacd(c.settings.ContractAddressSacd, &client).Return(mockSacd, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{1, 2, 4, 5},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           defaultAudience,
				}).Return("jwt", nil)
				mockSacd.EXPECT().CurrentPermissionRecord(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b111100111100)).Return(big.NewInt(0b111100111100), nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "eth token, multiple perms requested, fail on SACD, no privs",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &TokenRequest{
				TokenID:            123,
				Privileges:         []int64{1, 2, 4, 5},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				contractsMgr.EXPECT().GetSacd(c.settings.ContractAddressSacd, &client).Return(mockSacd, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				mockSacd.EXPECT().CurrentPermissionRecord(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b111100111100)).Return(big.NewInt(0b111100001100), nil)

				contractsMgr.EXPECT().GetMultiPrivilege("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144", &client).Return(mockMultiPriv, nil)
				mockMultiPriv.EXPECT().HasPrivilege(nil, big.NewInt(123), gomock.Any(), userEthAddr).Return(false, nil)
			},
			expectedCode: fiber.StatusBadRequest,
		},
		{
			name: "eth token, multiple perms requested, fail on SACD, succeed on privs",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &TokenRequest{
				TokenID:            123,
				Privileges:         []int64{1, 2, 4, 5},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				contractsMgr.EXPECT().GetSacd(c.settings.ContractAddressSacd, &client).Return(mockSacd, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				mockSacd.EXPECT().CurrentPermissionRecord(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b111100111100)).Return(big.NewInt(0b111100001100), nil)

				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{1, 2, 4, 5},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           defaultAudience,
				}).Return("jwt", nil)

				contractsMgr.EXPECT().GetMultiPrivilege("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144", &client).Return(mockMultiPriv, nil)
				mockMultiPriv.EXPECT().HasPrivilege(nil, big.NewInt(123), gomock.Any(), userEthAddr).Times(4).Return(true, nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "auth jwt with userId but no ethereum address",
			tokenClaims: jwt.MapClaims{
				"sub": "user-id-123",
				"nbf": time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup:    func() {},
			expectedCode: fiber.StatusUnauthorized,
		},
		{
			name: "auth jwt with audience",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              []string{"dimo.zone"},
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				Audience:           []string{"my-app", "foo"},
			},
			mockSetup: func() {
				contractsMgr.EXPECT().GetSacd(c.settings.ContractAddressSacd, &client).Return(mockSacd, nil)
				mockipfs.EXPECT().Fetch(gomock.Any(), gomock.Any()).Return(nil, errors.New("no valid doc"))
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{4},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           []string{"my-app", "foo"},
				}).Return("jwt", nil)
				mockSacd.EXPECT().CurrentPermissionRecord(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr).Return(emptyPermRecord, nil)
				mockSacd.EXPECT().GetPermissions(nil, common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"), big.NewInt(123), userEthAddr, big.NewInt(0b1100000000)).Return(big.NewInt(0b1100000000), nil)
			},
			expectedCode: fiber.StatusOK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBytes, _ := json.Marshal(tc.permissionTokenRequest)
			app := fiber.New()
			app.Post("/tokens/exchange", authInjectorTestHandler(tc.tokenClaims), c.GetDeviceCommandPermissionWithScope)

			// setup mock expectations
			tc.mockSetup()

			request := buildRequest("POST", "/tokens/exchange", string(jsonBytes))
			response, err := app.Test(request)
			require.NoError(t, err)

			body, _ := io.ReadAll(response.Body)
			assert.Equal(t, tc.expectedCode, response.StatusCode, "expected success")
			if tc.expectedCode == fiber.StatusOK {
				assert.Equal(t, "jwt", gjson.GetBytes(body, "token").Str)
			}
		})
	}
}

const (
	developerAuthToken = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImRkNTFkNDkwYjc1Y2VhOTNlMGI3YWI2YzcwODczNWVlN2FmZDBmMDgifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGltby56b25lIiwicHJvdmlkZXJfaWQiOiJ3ZWIzIiwic3ViIjoiQ2lvd2VEWmxNMlk1Um1FME1VUTFOV1kzTWpZd05UQkRNelZsWVRaQlJtVmtOalZsTURZME1XSTVOVGNTQkhkbFlqTSIsImF1ZCI6IjB4NmUzZjlGYTQxRDU1ZjcyNjA1MEMzNWVhNkFGZWQ2NWUwNjQxYjk1NyIsImV4cCI6MTcyNDI0NDE3NCwiaWF0IjoxNzIzMDM0NTc0LCJhdF9oYXNoIjoiZVpzS2p5SzB0TGY2UkFNZkxKM1AydyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZXRoZXJldW1fYWRkcmVzcyI6IjB4NmUzZjlGYTQxRDU1ZjcyNjA1MEMzNWVhNkFGZWQ2NWUwNjQxYjk1NyJ9.n7w63IvKTBqynVIggMCJAuty7P9nyCWugF0oxjipgzw9P7LvctzEXaheJmrWoP95QZJg9izaFWL2UoE4VpcnR4-_G6R2whZGV2aqlj8FQH1mQuznJZQyZUc6zKMi0wqedGEIYWBRI1zmXHy70_rXYnV4U4loPqKrXxXrhQ6oZWqCb9WxOdX5zf41LuYF6Ez2xk_jiciKxrvjoGtFsJK4fKhKRkzbO0i5IcdmQwrPEN75k8DxtYTHiYO8p_8BXY5Wej3lfEo6ZVtLumxfdkanILiOd-cY793Ru7sFvY6ObAsA9OLM-F1VmiRkCaHTaTK9t3DwPGmuDgduStFDLVX76Q`
	mobileAuthToken    = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImE0YWFiMzgzNTZkOWVmYjUyY2Q3MjY0YmI4ZDc4ZTU4ZWQwODJlNWEifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGltby56b25lIiwicHJvdmlkZXJfaWQiOiJ3ZWIzIiwic3ViIjoiQ2lvd2VHRTVNMkkzWW1NeFJUTTFOamcyTWpjNU5EZ3dORFpHTUdVME9EQTBRMk01UVdaRE1USTNOMlVTQkhkbFlqTSIsImF1ZCI6ImRpbW8tZHJpdmVyIiwiZXhwIjoxNzM3NTY2Mjk4LCJpYXQiOjE3MzYzNTY2OTgsImF0X2hhc2giOiJRcGJ0Zm1rMkVvUTAzMkFCS1VPZi13IiwiY19oYXNoIjoiN29RUmZoRi1meFAwQWNPbEE0N2ZJdyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZXRoZXJldW1fYWRkcmVzcyI6IjB4YTkzYjdiYzFFMzU2ODYyNzk0ODA0NkYwZTQ4MDRDYzlBZkMxMjc3ZSJ9.yQmArmywbuZm2LvNSvmretbg18cfBZmqR7FBEtJJy47YuqasyiNCjtnb1MM2yTnk_DWnMfEvtbKX8wG3fVfv777lcmwXzZZqVbZ0R9ekUXxi3mvSvgPe82C1OIa-B1Tep6PweW0oqr5OU_L17yxBEpFJ8lRVBYdLCPScVCWFHovLFulG2uEGWheuNcjAKxuB1yGzqGMK7JlpgzKPgUSuRweL3sR6Z7WKrefaZiHNwmknOfuZHMHO0z4EbEnemYvH6uNaGDbExd3VbOOXjzAOQMDeuluftCLAWuq0xIu4uLHfeQvkVzjnq7rVEM6lTOSITIdeapP2IDEKDTJY5Tx0qg`
)

func TestDevLicenseMiddleware(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "token-exchange-api").
		Logger()

	idSvc := mock_middleware.NewMockIdentityService(mockCtrl)

	tests := []struct {
		name             string
		token            string
		validDevLicense  bool
		developerLicense common.Address
		dimoMobile       bool
		expectedCode     int
		identityAPIError error
	}{
		{
			name:         "DIMO mobile",
			token:        mobileAuthToken,
			dimoMobile:   true,
			expectedCode: fiber.StatusOK,
		},
		{
			name:             "Developer license",
			token:            developerAuthToken,
			validDevLicense:  true,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     fiber.StatusOK,
		},
		{
			name:             "Invalid developer license",
			token:            developerAuthToken,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     fiber.StatusForbidden,
		},
		{
			name:             "Identity API Error",
			token:            developerAuthToken,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     fiber.StatusInternalServerError,
			identityAPIError: errors.New("random identity api error"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			devLicenseMiddleware := middleware.NewDevLicenseValidator(idSvc, logger)
			app := fiber.New()
			app.Get("/",
				func(c *fiber.Ctx) error {
					authHeader := c.Get("Authorization")
					tk := strings.TrimPrefix(authHeader, "Bearer ")
					token, _, _ := new(jwt.Parser).ParseUnverified(tk, jwt.MapClaims{})
					c.Locals("user", token)
					return c.Next()
				},

				devLicenseMiddleware,

				func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

			if !tc.dimoMobile {
				if tc.validDevLicense {
					idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(true, nil)
				} else {
					if tc.identityAPIError != nil {
						idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(false, tc.identityAPIError)
					} else {
						idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(false, nil)
					}
				}
			}

			request := buildRequest("GET", "/", "")
			request.Header.Set("Authorization", tc.token)
			response, err := app.Test(request)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedCode, response.StatusCode)

			if tc.expectedCode == fiber.StatusForbidden {
				body, _ := io.ReadAll(response.Body)
				assert.Equal(t, string(body), fmt.Sprintf("not a dev license: %s", tc.developerLicense))
			}

		})
	}
}

func Test_ProtobufSerializer(t *testing.T) {
	privs := []privileges.Privilege{1, 2, 3, 4}

	ce := tokenclaims.CloudEvents{
		Events: []tokenclaims.Event{
			{
				EventType: cloudevent.TypeAttestation,
				Source:    "0x123",
				IDs:       []string{"attestation-1"},
			},
			{
				EventType: cloudevent.TypeAttestation,
				Source:    "*",
			},
			{
				EventType: cloudevent.TypeAttestation,
				IDs:       []string{"attestation-7"},
				Source:    "*",
			},
			{
				EventType: cloudevent.TypeFingerprint,
				Source:    "*",
			},
		},
	}
	cc := tokenclaims.CustomClaims{
		ContractAddress: common.BigToAddress(big.NewInt(2)),
		TokenID:         "1",
		PrivilegeIDs:    privs,
		CloudEvents:     &ce,
	}

	val, err := cc.Proto()
	require.NoError(t, err)

	value := val.AsMap()

	privCheck, ok := value["privilege_ids"].([]any)
	require.True(t, ok, "expected privilege_ids to be included in output")
	require.Equal(t, len(privCheck), len(privs))

	ceCheck, ok := value["cloud_events"].([]any)
	require.True(t, ok, "expected cloud_events to be included in output")
	require.Equal(t, len(ceCheck), len(ce.Events))

}

func buildRequest(method, url, body string) *http.Request {
	req, _ := http.NewRequest(
		method,
		url,
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	return req
}

// authInjectorTestHandler injects fake jwt with sub
func authInjectorTestHandler(jwtClaims jwt.MapClaims) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
		c.Locals("user", token)
		return c.Next()
	}
}
