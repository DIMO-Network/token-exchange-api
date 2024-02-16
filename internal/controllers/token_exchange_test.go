package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/DIMO-Network/token-exchange-api/internal/config"
	mock_contracts "github.com/DIMO-Network/token-exchange-api/internal/contracts/mocks"
	mock_services "github.com/DIMO-Network/token-exchange-api/internal/services/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
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

	// todo will probably need a middleware here to set the c.Locals("user", token) with a test token
	app.Post("/tokens/exchange", c.GetDeviceCommandPermissionWithScope)
	// todo: setup mock expectations

	// todo: test just happy path with ethereum address
	pt := &PermissionTokenRequest{
		TokenID:            123,
		Privileges:         []int64{4},
		NFTContractAddress: "0x90c4d6113ec88dd4bdf12f26db2b3998fd13a144",
	}
	jsonBytes, _ := json.Marshal(pt)

	request := buildRequest("GET", "/tokens/exchange", string(jsonBytes))

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
