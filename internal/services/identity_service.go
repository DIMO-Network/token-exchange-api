package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

type IdentityController struct {
	logger      *zerolog.Logger
	client      *http.Client
	identityURL string
}

const IdentityAPINotFoundError = "NOT_FOUND"

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

	if len(response.Errors) >= 1 {
		var errs []string
		for _, e := range response.Errors {
			if e.Extensions.Code == IdentityAPINotFoundError {
				i.logger.Info().Msg(e.Message)
				continue
			}
			errs = append(errs, e.Message)
		}

		if len(errs) > 0 {
			errAll := errors.New(strings.Join(errs, ";"))
			i.logger.Err(errAll).Msg("failed to fetch dev license from identity api")
			return false, errAll
		}

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
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request failed making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response from identity api %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var respBody IdentityResponse
	if err := json.Unmarshal(body, &respBody); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL response: %v", err)
	}

	return &respBody, nil
}

type DeveloperLicense struct {
	Owner common.Address `json:"owner"`
}

type Data struct {
	DeveloperLicense *DeveloperLicense `json:"developerLicense"`
}

type ErrorDetail struct {
	Message    string   `json:"message"`
	Path       []string `json:"path"`
	Extensions struct {
		Code string `json:"code"`
	} `json:"extensions"`
}

type IdentityResponse struct {
	Data   *Data         `json:"data,omitempty"`
	Errors []ErrorDetail `json:"errors,omitempty"`
}
