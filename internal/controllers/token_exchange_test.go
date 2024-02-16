package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	mock_contracts "github.com/DIMO-Network/token-exchange-api/internal/contracts/mocks"
	"github.com/DIMO-Network/token-exchange-api/internal/services"
	mock_services "github.com/DIMO-Network/token-exchange-api/internal/services/mocks"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTokenExchangeController_GetDeviceCommandPermissionWithScope(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "devices-api").
		Logger()

	dexService := mock_services.NewMockDexService(mockCtrl)
	usersSvc := mock_services.NewMockUsersService(mockCtrl)
	contractsMgr := mock_contracts.NewMockContractsManager(mockCtrl)
	contractsInit := mock_contracts.NewMockContractCallInitializer(mockCtrl)

	// setup app and route req
	c := NewTokenExchangeController(&logger, &config.Settings{
		BlockchainNodeURL:        "http://testurl.com/mock",
		ContractAddressWhitelist: "",
	}, dexService, usersSvc, contractsMgr, contractsInit)
	app := fiber.New()
	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	// just happy path with ethereum address
	pt := &PermissionTokenRequest{
		TokenID:            123,
		Privileges:         []int64{4},
		NFTContractAddress: "0x90c4d6113ec88dd4bdf12f26db2b3998fd13a144",
	}
	jsonBytes, _ := json.Marshal(pt)

	app.Post("/tokens/exchange", authInjectorTestHandler(userEthAddr), c.GetDeviceCommandPermissionWithScope)
	// todo: setup mock expectations
	client := ethclient.Client{}
	contractsInit.EXPECT().InitContractCall("http://testurl.com/mock").Return(&client, nil)
	mockMultiPriv := mock_contracts.NewMockMultiPriv(mockCtrl)
	contractsMgr.EXPECT().GetMultiPrivilege(pt.NFTContractAddress, &client).Return(mockMultiPriv, nil)
	dexService.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
		UserEthAddress:     userEthAddr.Hex(),
		TokenID:            strconv.FormatInt(pt.TokenID, 10),
		PrivilegeIDs:       pt.Privileges,
		NFTContractAddress: pt.NFTContractAddress,
	}).Return("jwt", nil)
	mockMultiPriv.EXPECT().HasPrivilege(nil, big.NewInt(pt.TokenID), big.NewInt(pt.Privileges[0]), &userEthAddr).Return(true, nil)

	request := buildRequest("POST", "/tokens/exchange", string(jsonBytes))

	response, _ := app.Test(request)
	body, _ := io.ReadAll(response.Body)
	fmt.Println("response body: " + string(body))
	assert.Equal(t, fiber.StatusOK, response.StatusCode, "expected success")

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
func authInjectorTestHandler(ethAddr common.Address) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": ethAddr.Hex(),
			"nbf":              time.Now().Unix(),
		})

		c.Locals("user", token)
		return c.Next()
	}
}
