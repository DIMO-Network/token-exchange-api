package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/DIMO-Network/token-exchange-api/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

type IdentityApiController struct {
	logger      *zerolog.Logger
	identityUrl string
}

func NewIdentityApiController(logger *zerolog.Logger, settings *config.Settings) *IdentityApiController {
	return &IdentityApiController{
		logger:      logger,
		identityUrl: settings.IdentityAPIURL,
	}
}

func (i *IdentityApiController) isDevLicense(ctx context.Context, ethAddr common.Address) (bool, error) {
	requestBody := map[string]any{
		"query": `{
			query ($clientId: clientId!) {
			  developerLicense(by: {clientId: $clientId}) {
				  id
				  name
				  email
			  }
		  }`,
		"variables": map[string]any{
			"clientId": ethAddr.Hex(),
		},
	}

	reqBytes, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.identityUrl, bytes.NewBuffer(reqBytes))
	if err != nil {
		return false, fmt.Errorf("failed to create identity API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send GraphQL request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read GraphQL response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("non-200 response from GraphQL API: %d, '%s'", resp.StatusCode, string(bodyBytes))
	}

	var respBody IdentityResponse
	if err := json.Unmarshal(bodyBytes, &respBody); err != nil {
		return false, fmt.Errorf("failed to unmarshal GraphQL response: %w", err)
	}

	if len(respBody.Errors) > 0 {
		if respBody.Errors[0].Message == "sql: no rows in result set" {
			return false, nil
		}

		return false, fmt.Errorf("GraphQL API error: %s", respBody.Errors[0].Message)
	}

	return true, nil

}

type IdentityResponse struct {
	Data   DevLicenseResponse `json:"data"`
	Errors []GraphQLError     `json:"errors"`
}

type DevLicenseResponse struct {
	DevLicense []LicenseInfos `json:"developerLicense"`
}

type LicenseInfos struct {
	Owner    common.Address `json:"owner"`
	ClientId common.Address `json:"clientId"`
	TokenId  big.Int        `json:"tokenId"`
}

type GraphQLError struct {
	Message string `json:"message"`
}
