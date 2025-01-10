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
	queryDevLicenseByClientID = `query ($clientId: Address!) 
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
		"query": queryDevLicenseByClientID,
		"variables": map[string]any{
			"clientId": ethAddr.Hex(),
		},
	}

	response, err := i.executeQuery(ctx, requestBody)
	if err != nil {
		return false, err
	}
	fmt.Println(response)
	if len(response.Errors) >= 1 {
		return false, nil
	}

	return true, nil

}

func (i *IdentityController) executeQuery(ctx context.Context, requestBody map[string]any) (*IdentityResponse, error) {
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.identityURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request failed making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response from identity api %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var respBody IdentityResponse
	if err := json.Unmarshal(body, &respBody); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL response: %v", err)
	}

	return &respBody, nil
}

type DeveloperLicense struct {
	Alias string         `json:"alias"`
	Owner common.Address `json:"owner"`
}

type Data struct {
	DeveloperLicense *DeveloperLicense `json:"developerLicense"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

type IdentityResponse struct {
	Data   *Data         `json:"data,omitempty"`
	Errors []ErrorDetail `json:"errors,omitempty"`
}
