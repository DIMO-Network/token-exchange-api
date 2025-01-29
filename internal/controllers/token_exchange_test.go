package controllers

import (
	"encoding/base64"
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
	"github.com/DIMO-Network/token-exchange-api/internal/middleware/dex"
	mock_middleware "github.com/DIMO-Network/token-exchange-api/internal/middleware/mocks"
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
	"google.golang.org/protobuf/proto"
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

const (
	developerAuthToken = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImRkNTFkNDkwYjc1Y2VhOTNlMGI3YWI2YzcwODczNWVlN2FmZDBmMDgifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGltby56b25lIiwicHJvdmlkZXJfaWQiOiJ3ZWIzIiwic3ViIjoiQ2lvd2VEWmxNMlk1Um1FME1VUTFOV1kzTWpZd05UQkRNelZsWVRaQlJtVmtOalZsTURZME1XSTVOVGNTQkhkbFlqTSIsImF1ZCI6IjB4NmUzZjlGYTQxRDU1ZjcyNjA1MEMzNWVhNkFGZWQ2NWUwNjQxYjk1NyIsImV4cCI6MTcyNDI0NDE3NCwiaWF0IjoxNzIzMDM0NTc0LCJhdF9oYXNoIjoiZVpzS2p5SzB0TGY2UkFNZkxKM1AydyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZXRoZXJldW1fYWRkcmVzcyI6IjB4NmUzZjlGYTQxRDU1ZjcyNjA1MEMzNWVhNkFGZWQ2NWUwNjQxYjk1NyJ9.n7w63IvKTBqynVIggMCJAuty7P9nyCWugF0oxjipgzw9P7LvctzEXaheJmrWoP95QZJg9izaFWL2UoE4VpcnR4-_G6R2whZGV2aqlj8FQH1mQuznJZQyZUc6zKMi0wqedGEIYWBRI1zmXHy70_rXYnV4U4loPqKrXxXrhQ6oZWqCb9WxOdX5zf41LuYF6Ez2xk_jiciKxrvjoGtFsJK4fKhKRkzbO0i5IcdmQwrPEN75k8DxtYTHiYO8p_8BXY5Wej3lfEo6ZVtLumxfdkanILiOd-cY793Ru7sFvY6ObAsA9OLM-F1VmiRkCaHTaTK9t3DwPGmuDgduStFDLVX76Q`
	mobileAuthToken    = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImE0YWFiMzgzNTZkOWVmYjUyY2Q3MjY0YmI4ZDc4ZTU4ZWQwODJlNWEifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGltby56b25lIiwicHJvdmlkZXJfaWQiOiJ3ZWIzIiwic3ViIjoiQ2lvd2VHRTVNMkkzWW1NeFJUTTFOamcyTWpjNU5EZ3dORFpHTUdVME9EQTBRMk01UVdaRE1USTNOMlVTQkhkbFlqTSIsImF1ZCI6ImRpbW8tZHJpdmVyIiwiZXhwIjoxNzM3NTY2Mjk4LCJpYXQiOjE3MzYzNTY2OTgsImF0X2hhc2giOiJRcGJ0Zm1rMkVvUTAzMkFCS1VPZi13IiwiY19oYXNoIjoiN29RUmZoRi1meFAwQWNPbEE0N2ZJdyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZXRoZXJldW1fYWRkcmVzcyI6IjB4YTkzYjdiYzFFMzU2ODYyNzk0ODA0NkYwZTQ4MDRDYzlBZkMxMjc3ZSJ9.yQmArmywbuZm2LvNSvmretbg18cfBZmqR7FBEtJJy47YuqasyiNCjtnb1MM2yTnk_DWnMfEvtbKX8wG3fVfv777lcmwXzZZqVbZ0R9ekUXxi3mvSvgPe82C1OIa-B1Tep6PweW0oqr5OU_L17yxBEpFJ8lRVBYdLCPScVCWFHovLFulG2uEGWheuNcjAKxuB1yGzqGMK7JlpgzKPgUSuRweL3sR6Z7WKrefaZiHNwmknOfuZHMHO0z4EbEnemYvH6uNaGDbExd3VbOOXjzAOQMDeuluftCLAWuq0xIu4uLHfeQvkVzjnq7rVEM6lTOSITIdeapP2IDEKDTJY5Tx0qg`
	mobileAuthToken2   = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjQyNDY3ZmE3Zjg0OTNiZjM2ODk5ZTAyNDAyMzgwODkwNzA1N2RiMWUifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGV2LmRpbW8uem9uZSIsInByb3ZpZGVyX2lkIjoid2ViMyIsInN1YiI6IkNpb3dlRE13TkRKRk1HSkNZV1V5TnpZMU1UWXhaREV6Tm1GRVpUaENOakkwWWpoRU16WkNOa1U0WkRnU0JIZGxZak0iLCJhdWQiOiJkaW1vLWRyaXZlciIsImV4cCI6MTczOTIyMTg3MCwiaWF0IjoxNzM4MDEyMjcwLCJhdF9oYXNoIjoiZWlKM0xabGNQZjk3QjhPZHI1cU9jUSIsImNfaGFzaCI6IkRNbmVlQlF6VnhvQ3V2MjJMTGtkcEEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImV0aGVyZXVtX2FkZHJlc3MiOiIweDMwNDJFMGJCYWUyNzY1MTYxZDEzNmFEZThCNjI0YjhEMzZCNkU4ZDgifQ.nXhuaA_kJpRRHvOaFosQqT6SeOx8EcAl7vFbr2iqPK2Z4HVcFp20oZSiYE9AfLvv8tKCY3PcP3ZtNfeJIs7mJbLsfPjK4G4vCmA1rItyQUSf5ByvEpXLx2leLKbsYliByiNPN-dYMooHVJUHzT78NrUJwVYeVyq_kUuXBOPD3TEoV0awfVReIQxmxD9OJz68jOsLZn14amrGd0a1MMxLHgoqtYZewF-wiUUi51Bu4aEXVD1t_fH8jiEZGg32IxFB8MaXILdT3SZd3t0pox39SkR6etIip4PpdOhRduZ-b5iT3bDSMcTAzChSUweMeKt5D9SDhV6oK8GxOSOxxAau_A`
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
	}{
		{
			name:         "DIMO mobile",
			token:        mobileAuthToken2,
			dimoMobile:   true,
			expectedCode: fiber.StatusOK,
		},
		{
			name:             "Developer license",
			token:            mobileAuthToken2,
			validDevLicense:  true,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     fiber.StatusOK,
		},
		// {
		// 	name:             "Invalid developer license",
		// 	token:            developerAuthToken,
		// 	developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
		// 	expectedCode:     fiber.StatusForbidden,
		// },
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
					idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(false, nil)
				}
			}

			request := buildRequest("GET", "/", "")
			request.Header.Set("Authorization", tc.token)
			response, err := app.Test(request)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedCode, response.StatusCode)

		})
	}
}

func Test_ExamineJWT(t *testing.T) {
	// examineJWT1_MobileApp := "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjQyNDY3ZmE3Zjg0OTNiZjM2ODk5ZTAyNDAyMzgwODkwNzA1N2RiMWUifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGV2LmRpbW8uem9uZSIsInByb3ZpZGVyX2lkIjoid2ViMyIsInN1YiI6IkNpb3dlRE13TkRKRk1HSkNZV1V5TnpZMU1UWXhaREV6Tm1GRVpUaENOakkwWWpoRU16WkNOa1U0WkRnU0JIZGxZak0iLCJhdWQiOiJkaW1vLWRyaXZlciIsImV4cCI6MTczOTIyNDEzMiwiaWF0IjoxNzM4MDE0NTMyLCJhdF9oYXNoIjoiaHZZTUtWenRDNjUwYldOampqTEwwdyIsImNfaGFzaCI6Ik45YmJlV0g1ZFZFb2xKMGxpM1oxVlEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImV0aGVyZXVtX2FkZHJlc3MiOiIweDMwNDJFMGJCYWUyNzY1MTYxZDEzNmFEZThCNjI0YjhEMzZCNkU4ZDgifQ.PtOVINZ6AgvQwI6nN90nttulMbGb8y8ruYMP9IZ0crjUb0iEomW-4eRNOUZIN7BnrXxZt-5Yg94BpTyU18Mo6VPvnsJLRAW4Ii9heYmWGe3wTGlkMFFQahhrxT_ALELuc5qxMK7_96_JtCs-8TE2tFWyLtEsdFsCmtHliD8CqJ-6W8m5UcqoSy2kWRnuIlY59t_VV9RuL4OWtGk0wOM3aOvQ7Os_jtmFAST_iaE9FMoWxLQmgfdFFJ8uLMPhAbAVxruKMZZ8_3qzYm9TIw6tSKYZ8EpN-DOGpimKcGJxdN4qD1sHTVbEka-ehPnFgAFlKrk-ZKTMrl2pBa_MKxFY0w"
	examineJWT2_MintVehicleWorker := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRjNGYwODQwMDcxNTcwMWVhZWMxYTI1OWZmYjk2Y2M3YThmYmIzMzQifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGV2LmRpbW8uem9uZSIsInByb3ZpZGVyX2lkIjoid2ViMyIsInN1YiI6IkNpb3dlRFV4TmpJNVpEWkRaV1JqTjBNd1FrUTROV1l6TXpaQlFUYzNPRGMzTnpReFkyUXpOemcxTXpFU0JIZGxZak0iLCJhdWQiOiJkaW1vLWRyaXZlciIsImV4cCI6MTczOTI4NzIxMywiaWF0IjoxNzM4MDc3NjEzLCJhdF9oYXNoIjoiWkh0WW1qaGp4NDI3cE1MOXlBQTVMZyIsImNfaGFzaCI6IlhZZUZfWldtUkxYWHA1TzQ5ckhnNWciLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImV0aGVyZXVtX2FkZHJlc3MiOiIweDUxNjI5ZDZDZWRjN0MwQkQ4NWYzMzZBQTc3ODc3NzQxY2QzNzg1MzEifQ.YZFdCvw3pybF8Z0O5gZjOEZz7P0CVj1fuv9Rp4ABVF6WDL138Lg00eKORqz5n5S78MLG6FstdClzNAeRL2YbPZpAd62dLDVPQTC1JWeolW97FG_ttnxoCGWtlV4V51HQAqgDsGhEwDyv9w-VCcjXwezfmHiXXaVQnXvYCBM-Xe59lZ-X2W3_U3r7Ae-BtXA9ym8HDd-yQrBzpcjrqbW61N-jXjeXtbrqiau_IDWnS7lWiYBpHD3lfr0xCl3z8qz8UgLn21Wjkg49En4B4RfLL4mOqFWy5QTx5GnRS-57M4pW26ew1rGkOb5A-6HpcwthgL5SmKfqAaa_oFRXAngUXA"
	tests := []struct {
		name             string
		token            string
		validDevLicense  bool
		developerLicense common.Address
		dimoMobile       bool
		expectedCode     int
	}{
		{
			name:         "DIMO mobile",
			token:        examineJWT2_MintVehicleWorker,
			dimoMobile:   true,
			expectedCode: fiber.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Get("/",
				func(c *fiber.Ctx) error {
					authHeader := c.Get("Authorization")
					tk := strings.TrimPrefix(authHeader, "Bearer ")
					token, _, _ := new(jwt.Parser).ParseUnverified(tk, jwt.MapClaims{})
					c.Locals("user", token)
					return c.Next()
				},

				func(c *fiber.Ctx) error {
					fmt.Println(1)
					token, ok := c.Locals("user").(*jwt.Token)
					if !ok {
						return fiber.NewError(fiber.StatusBadRequest, "failed to pull token from request context")
					}
					fmt.Println(2)
					// get audience from claim to check if it is coming from dimo mobile
					aud, err := token.Claims.GetAudience()
					if err != nil {
						return fiber.NewError(fiber.StatusBadRequest, "failed to get audience from token claims")
					}
					fmt.Println(3, aud)
					// no additional checks for mobile app
					// TODO(ae): add additional security here eventually
					// if slices.Contains(aud, mobileAppAudience) {
					// 	return c.Next()
					// }
					fmt.Println(4)
					// if not dimo mobile, make sure the subject is a dev license
					subj, err := token.Claims.GetSubject()
					if err != nil {
						return fiber.NewError(fiber.StatusBadRequest, "failed to get subject from token claims")
					}
					fmt.Println(5)
					decoded, err := base64.RawURLEncoding.DecodeString(subj)
					if err != nil {
						return fiber.NewError(fiber.StatusBadRequest, "failed to decode subject")
					}
					fmt.Println(6)
					var user dex.User
					if err = proto.Unmarshal(decoded, &user); err != nil {
						return fiber.NewError(fiber.StatusBadRequest, "failed to parse subject")
					}

					fmt.Println(7, user.ConnId, user.UserId)

					return c.Next()
				},

				func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

			request := buildRequest("GET", "/", "")
			request.Header.Set("Authorization", tc.token)
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
