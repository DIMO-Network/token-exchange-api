package httpcontroller_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/DIMO-Network/token-exchange-api/internal/controllers/httpcontroller"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware"
	"github.com/DIMO-Network/token-exchange-api/internal/middleware/dex"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	"github.com/DIMO-Network/token-exchange-api/internal/services/access"
	"github.com/DIMO-Network/token-exchange-api/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
)

var defaultAudience = []string{"dimo.zone"}

//go:generate go tool mockgen -source ./token_exchange.go -destination ./token_exchange_mock_test.go -package httpcontroller_test
//go:generate go tool mockgen -source ../../middleware/valid_dev_license.go -destination ./identity_service_mock_test.go -package httpcontroller_test
func TestTokenExchangeController_ExchangeToken(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	dexService := NewMockDexService(mockCtrl)
	mockIdent := NewMockIdentityService(mockCtrl)
	mockAccess := NewMockAccessService(mockCtrl)

	// setup app and route req
	c, err := httpcontroller.NewTokenExchangeController(&config.Settings{
		DIMORegistryChainID: 1,
	}, dexService, mockAccess)
	require.NoError(t, err, "Failed to initialize token exchange controller")

	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	devLicenseAddr := common.HexToAddress("0x69F5C4D08F6bC8cD29fE5f004d46FB566270868d")

	u := dex.User{
		ConnId: "web3",
		UserId: devLicenseAddr.Hex(),
	}

	b, err := proto.Marshal(&u)
	require.NoError(t, err)

	devLicenseSub := base64.RawURLEncoding.EncodeToString(b)

	tests := []struct {
		name                   string
		tokenClaims            jwt.MapClaims
		userEthAddr            *common.Address
		permissionTokenRequest *httpcontroller.TokenRequest
		mockSetup              func()
		expectedCode           int
	}{
		{
			name: "auth jwt with ethereum addr",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.NFTAccessRequest{
					Asset: cloudevent.ERC721DID{
						ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
						TokenID:         big.NewInt(123),
						ChainID:         1,
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
				}, userEthAddr).Return(nil)
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					NFTAccessRequest: &access.NFTAccessRequest{
						Asset: cloudevent.ERC721DID{
							ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
					},
					Audience:        defaultAudience,
					ResponseSubject: "dimo-driver",
				}).Return("jwt", nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "valid request from developer license",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": devLicenseAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              devLicenseAddr.Hex(),
				"sub":              devLicenseSub,
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), devLicenseAddr).Return(true, nil)
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.NFTAccessRequest{
					Asset: cloudevent.ERC721DID{
						ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
						TokenID:         big.NewInt(123),
						ChainID:         1,
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
				}, devLicenseAddr).Return(nil)
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					NFTAccessRequest: &access.NFTAccessRequest{
						Asset: cloudevent.ERC721DID{
							ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
					},
					Audience:        defaultAudience,
					ResponseSubject: devLicenseAddr.Hex(),
				}).Return("jwt", nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "eth token, multiple perms, success on SACD",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{1, 2, 4, 5},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup: func() {
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.NFTAccessRequest{
					Asset: cloudevent.ERC721DID{
						ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
						TokenID:         big.NewInt(123),
						ChainID:         1,
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[1], tokenclaims.PrivilegeIDToName[2], tokenclaims.PrivilegeIDToName[4], tokenclaims.PrivilegeIDToName[5]},
				}, userEthAddr).Return(nil)
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					NFTAccessRequest: &access.NFTAccessRequest{
						Asset: cloudevent.ERC721DID{
							ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[1], tokenclaims.PrivilegeIDToName[2], tokenclaims.PrivilegeIDToName[4], tokenclaims.PrivilegeIDToName[5]},
					},
					Audience:        defaultAudience,
					ResponseSubject: "dimo-driver",
				}).Return("jwt", nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "auth jwt with userId but no ethereum address",
			tokenClaims: jwt.MapClaims{
				"sub": "user-id-123",
				"nbf": time.Now().Unix(),
				"aud": "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
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
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
				Audience:           []string{"my-app", "foo"},
			},
			mockSetup: func() {
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.NFTAccessRequest{
					Asset: cloudevent.ERC721DID{
						ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
						TokenID:         big.NewInt(123),
						ChainID:         1,
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
				}, userEthAddr).Return(nil)
				dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					NFTAccessRequest: &access.NFTAccessRequest{
						Asset: cloudevent.ERC721DID{
							ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
					},
					Audience:        []string{"my-app", "foo"},
					ResponseSubject: "dimo-driver",
				}).Return("jwt", nil)
			},
			expectedCode: fiber.StatusOK,
		},
		{
			name: "Fail: must pass privilege or cloud event request",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID: 123,
				CloudEvents: httpcontroller.CloudEvents{
					Events: []models.EventFilter{},
				},
				NFTContractAddress: "0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144",
			},
			mockSetup:    func() {},
			expectedCode: fiber.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBytes, _ := json.Marshal(tc.permissionTokenRequest)
			app := fiber.New(fiber.Config{
				ErrorHandler: errorHandlerCopy,
			})
			app.Post("/tokens/exchange", authInjectorTestHandler(tc.tokenClaims), middleware.NewDevLicenseValidator(mockIdent, zerolog.Nop()), c.ExchangeToken)

			// setup mock expectations
			tc.mockSetup()

			request := buildRequest("POST", "/tokens/exchange", string(jsonBytes))
			response, err := app.Test(request, -1)
			require.NoError(t, err)

			body, _ := io.ReadAll(response.Body)

			require.Equal(t, tc.expectedCode, response.StatusCode, "expected success")
			if tc.expectedCode == fiber.StatusOK {
				require.Equal(t, "jwt", gjson.GetBytes(body, "token").Str)
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

	idSvc := NewMockIdentityService(mockCtrl)

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

			var sub string

			app.Get("/",
				func(c *fiber.Ctx) error {
					authHeader := c.Get("Authorization")
					tk := strings.TrimPrefix(authHeader, "Bearer ")
					token, _, _ := new(jwt.Parser).ParseUnverified(tk, jwt.MapClaims{})
					c.Locals("user", token)

					return c.Next()
				},
				devLicenseMiddleware,
				func(c *fiber.Ctx) error {
					var err error
					sub, err = middleware.GetResponseSubject(c)
					if err != nil {
						require.NoError(t, err, "subject extraction failed")
					}
					return c.Next()
				},
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

			if tc.dimoMobile {
				assert.Equal(t, "dimo-driver", sub)
			} else if tc.validDevLicense && tc.identityAPIError == nil {
				assert.Equal(t, tc.developerLicense.Hex(), sub)
			}

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
			{
				EventType: tokenclaims.GlobalIdentifier,
				Source:    "0x123",
				IDs:       []string{"attestation-10"},
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

	ceCheck, ok := value["cloud_events"].(map[string]any)
	require.True(t, ok, "expected cloud_events to be included in output")

	events, ok := ceCheck["events"].([]any)
	require.True(t, ok, "expected events to be valid key in cloud_events")

	require.Equal(t, len(events), len(ce.Events))

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

type codeResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// errorHandlerCopy is a copy of the error handler from the app package because we don't want cyclic imports
func errorHandlerCopy(ctx *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError // Default 500 statuscode
	message := "Internal error."

	var fiberErr *fiber.Error
	var richErr richerrors.Error
	if errors.As(err, &fiberErr) {
		code = fiberErr.Code
		message = fiberErr.Message
	} else if errors.As(err, &richErr) {
		message = richErr.ExternalMsg
		if richErr.Code != 0 {
			code = richErr.Code
		}
	}

	// log all errors except 404
	if code != fiber.StatusNotFound {
		logger := zerolog.Ctx(ctx.UserContext())
		logger.Err(err).Int("httpStatusCode", code).
			Str("httpPath", strings.TrimPrefix(ctx.Path(), "/")).
			Str("httpMethod", ctx.Method()).
			Msg("caught an error from http request")
	}

	return ctx.Status(code).JSON(codeResp{Code: code, Message: message})
}
