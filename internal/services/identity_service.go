package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

//go:generate mockgen -source identity_service.go -destination mocks/identity_service_mock.go
type IdentityService interface {
	IsDevLicense(ctx context.Context, ethAddr common.Address) (bool, error)
}

type IdentityController struct {
	logger      *zerolog.Logger
	client      *http.Client
	identityURL string
}

func NewIdentityController(logger *zerolog.Logger, settings *config.Settings) *IdentityController {
	return &IdentityController{
		logger:      logger,
		client:      &http.Client{},
		identityURL: settings.IdentityURL,
	}
}

const (
	queryDevLicenseByClientId = `query ($clientId: Address!) 
	{
		developerLicense( by: { clientId: $clientId }) 
			{
  				owner
  				alias    
			}
	}`
)

// IsDevLicense checks whether the eth address represents a dev license client id
func (i *IdentityController) IsDevLicense(ctx context.Context, ethAddr common.Address) (bool, error) {
	requestBody := map[string]any{
		"query": queryDevLicenseByClientId,
		"variables": map[string]any{
			"clientId": ethAddr.Hex(),
		},
	}

	response, err := i.executeQuery(requestBody)
	if err != nil {
		return false, err
	}

	if len(response.Errors) > 1 {
		return false, nil
	}

	return true, nil

}

func (i *IdentityController) executeQuery(requestBody map[string]any) (*IdentityResponse, error) {
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, i.identityURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request failed making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed query response")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response from identity api %d", resp.StatusCode)
	}

	var respBody IdentityResponse
	if err := json.Unmarshal(body, &respBody); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL response: %w", err)
	}

	return &respBody, nil
}

type DeveloperLicense struct {
	Owner    string         `json:"owner"`
	Alias    string         `json:"alias"`
	ClientId common.Address `json:"clientId"`
}

type Data struct {
	DeveloperLicense DeveloperLicense `json:"developerLicense"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

type IdentityResponse struct {
	Data   *Data         `json:"data,omitempty"`
	Errors []ErrorDetail `json:"errors,omitempty"`
}
