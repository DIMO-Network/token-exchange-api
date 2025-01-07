package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	mock_contracts "github.com/DIMO-Network/token-exchange-api/internal/contracts/mocks"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	mock_services "github.com/DIMO-Network/token-exchange-api/internal/services/mocks"
	"github.com/DIMO-Network/users-api/pkg/grpc"
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

func TestTokenExchangeController_GetDeviceCommandPermissionWithScope(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "token-exchange-api").
		Logger()

	dexService := mock_services.NewMockDexService(mockCtrl)
	usersSvc := mock_services.NewMockUsersService(mockCtrl)
	contractsMgr := mock_contracts.NewMockManager(mockCtrl)
	contractsInit := mock_contracts.NewMockContractCallInitializer(mockCtrl)
	mockMultiPriv := mock_contracts.NewMockMultiPriv(mockCtrl)
	mockSacd := mock_contracts.NewMockSacd(mockCtrl)

	// setup app and route req
	c := NewTokenExchangeController(&logger, &config.Settings{
		BlockchainNodeURL:        "http://testurl.com/mock",
		ContractAddressWhitelist: "",
		ContractAddressSacd:      "0xa6",
	}, dexService, usersSvc, contractsMgr, contractsInit)
	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	tests := []struct {
		name                   string
		tokenClaims            jwt.MapClaims
		userEthAddr            *common.Address
		permissionTokenRequest *PermissionTokenRequest
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
			permissionTokenRequest: &PermissionTokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{4},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           defaultAudience,
				}).Return("jwt", nil)
				mockMultiPriv.EXPECT().HasPrivilege(nil, big.NewInt(123), big.NewInt(4), userEthAddr).
					Return(true, nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "auth jwt with userId",
			tokenClaims: jwt.MapClaims{
				"sub": "user-id-123",
				"nbf": time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &PermissionTokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{4},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           defaultAudience,
				}).Return("jwt", nil)
				mockMultiPriv.EXPECT().HasPrivilege(nil, big.NewInt(123), big.NewInt(4), userEthAddr).
					Return(true, nil)
				e := userEthAddr.Hex()
				usersSvc.EXPECT().GetUserByID(gomock.Any(), "user-id-123").Return(&grpc.User{
					EthereumAddress: &e,
				}, nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "auth jwt with audience",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              []string{"dimo.zone"},
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &PermissionTokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				Audience:           []string{"my-app", "foo"},
			},
			mockSetup: func() {
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					UserEthAddress:     userEthAddr.Hex(),
					TokenID:            strconv.FormatInt(123, 10),
					PrivilegeIDs:       []int64{4},
					NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
					Audience:           []string{"my-app", "foo"},
				}).Return("jwt", nil)
				mockMultiPriv.EXPECT().HasPrivilege(nil, big.NewInt(123), big.NewInt(4), userEthAddr).
					Return(true, nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "auth jwt with userId no user found",
			tokenClaims: jwt.MapClaims{
				"sub": "user-id-123",
				"nbf": time.Now().Unix(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &PermissionTokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				usersSvc.EXPECT().GetUserByID(gomock.Any(), "user-id-123").Return(nil, fmt.Errorf("not found"))
			},
			expectedCode: fiber.StatusInternalServerError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBytes, _ := json.Marshal(tc.permissionTokenRequest)
			app := fiber.New()
			app.Post("/tokens/exchange", authInjectorTestHandler(tc.tokenClaims), c.GetDeviceCommandPermissionWithScope)

			// setup mock expectations
			tc.mockSetup()
			client := ethclient.Client{}
			contractsInit.EXPECT().InitContractCall("http://testurl.com/mock").Return(&client, nil)

			contractsMgr.EXPECT().GetMultiPrivilege(tc.permissionTokenRequest.NFTContractAddress, &client).Return(mockMultiPriv, nil)
			contractsMgr.EXPECT().GetSacd(c.settings.ContractAddressSacd, &client).Return(mockSacd, nil)

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

func TestValidDevLicenseMiddleware(t *testing.T) {
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIweDI5ODZGNjVlRTlhNDhDMzhGNjRDN2JhREMwZGNiMDBkYjAxRjlCMWEiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6IjB4Mjk4NkY2NWVFOWE0OEMzOEY2NEM3YmFEQzBkY2IwMGRiMDFGOUIxYSJ9.GcNCTtmfjIknGXavT5umyiBW1sqTTbDDMcy-zPK-Lvo

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	idSvc := mock_services.NewMockIdentityService(mockCtrl)

	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "token-exchange-api").
		Logger()

	tests := []struct {
		name            string
		appJWTClaims    jwt.MapClaims
		validDevLicense bool
		dimoMobile      bool
		expectedCode    int
	}{
		{
			name: "not dimo mobile, audience is dev license matches sub",
			appJWTClaims: jwt.MapClaims{
				"aud": userEthAddr.Hex(),
				"sub": userEthAddr.Hex(),
			},
			validDevLicense: true,
			expectedCode:    fiber.StatusOK,
		},
		{
			name: "not dimo mobile, aud is invalid",
			appJWTClaims: jwt.MapClaims{
				"aud": userEthAddr.Hex(),
				"sub": userEthAddr.Hex(),
			},
			validDevLicense: false,
			expectedCode:    fiber.StatusForbidden,
		},
		{
			name: "aud is dimo mobile app, the rest doesn't matter",
			appJWTClaims: jwt.MapClaims{
				"aud": middleware.MobileAppAudience,
				"sub": common.BigToAddress(big.NewInt(1)).Hex(),
			},
			dimoMobile:      true,
			validDevLicense: true,
			expectedCode:    fiber.StatusOK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			devLicenseMiddleware := middleware.NewDevLicenseValidator(&config.Settings{}, logger, idSvc)
			app := fiber.New()
			app.Use("*", authInjectorTestHandler(tc.appJWTClaims), devLicenseMiddleware)
			app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

			if !tc.dimoMobile {
				if tc.validDevLicense {
					idSvc.EXPECT().IsDevLicense(gomock.Any(), common.HexToAddress(tc.appJWTClaims["sub"].(string))).Return(true, nil)
				} else {
					idSvc.EXPECT().IsDevLicense(gomock.Any(), common.HexToAddress(tc.appJWTClaims["sub"].(string))).Return(false, nil)
				}
			}

			request := buildRequest("GET", "/", "")
			response, err := app.Test(request)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedCode, response.StatusCode)

		})
	}
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
