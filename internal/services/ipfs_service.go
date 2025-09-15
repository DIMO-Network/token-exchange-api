package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/rs/zerolog"
)

const (
	DefaultIPFSPrefix  = "ipfs://"
	DefaultIPFSTimeout = 30 * time.Second
)

type IPFSClient struct {
	logger      *zerolog.Logger
	client      *http.Client
	ipfsBaseURL *url.URL
	timeout     time.Duration
}

func NewIPFSClient(logger *zerolog.Logger, ipfsBaseURL, ipfsTimeout string) (*IPFSClient, error) {
	ipfsURL, err := url.Parse(ipfsBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid IPFS base URL: %w", err)
	}

	timout, err := time.ParseDuration(ipfsTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ipfs duration: %w", err)
	}

	if timout.Seconds() == 0 {
		timout = DefaultIPFSTimeout
	}

	return &IPFSClient{
		logger:      logger,
		client:      &http.Client{},
		ipfsBaseURL: ipfsURL,
		timeout:     timout,
	}, nil
}

// FetchFromIPFS retrieves content from IPFS using the provided content identifier (CID).
// It constructs a URL using the configured IPFS base URL and the CID, then makes an HTTP GET
// request to fetch the content.
//
// Parameters:
//   - ctx: The context for the HTTP request, which can be used for cancellation and timeouts
//   - cid: The IPFS content identifier, with or without the "ipfs://" prefix
//
// Returns:
//   - []byte: The content retrieved from IPFS as a byte slice
//   - error: An error if the request fails at any stage (URL construction, HTTP request creation,
//     request execution, or response reading)
func (i *IPFSClient) Fetch(ctx context.Context, cid string) ([]byte, error) {
	cid = strings.TrimPrefix(cid, DefaultIPFSPrefix)
	ipfsURL := i.ipfsBaseURL.JoinPath(cid).String()

	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipfsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid ipfs status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetValidSacdDoc fetches and validates a SACD document from IPFS.
// It retrieves the document using the provided source identifier, attempts to parse it as JSON,
// and verifies that it has the correct type for a DIMO SACD document.
//
// Parameters:
//   - ctx: The context for the IPFS request, which can be used for cancellation and timeouts
//   - source: The IPFS content identifier (CID) for the SACD document, typically with an "ipfs://" prefix
//
// Returns:
//   - *cloudevent.RawEvent: A pointer to the parsed raw cloud event if valid
//   - error: An error if the document could not be fetched, parsed, or doesn't have the correct type
func (i *IPFSClient) GetValidSacdDoc(ctx context.Context, source string) (*cloudevent.RawEvent, error) {
	sacdDoc, err := i.Fetch(ctx, source)
	if err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to fetch source document from IPFS: %w", err),
			ExternalMsg: "failed to fetch source document from IPFS",
		}
	}

	var record cloudevent.RawEvent
	if err := json.Unmarshal(sacdDoc, &record); err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			Err:         fmt.Errorf("failed to parse sacd data: %w", err),
			ExternalMsg: "failed to parse sacd data",
		}
	}

	if record.Type != cloudevent.TypeSACD && record.Type != cloudevent.TypeSACDTemplate {
		return nil, richerrors.Error{
			Code:        http.StatusUnauthorized,
			ExternalMsg: fmt.Sprintf("invalid type: expected '%s' or '%s', got '%s'", cloudevent.TypeSACD, cloudevent.TypeSACDTemplate, record.Type),
		}
	}

	return &record, nil
}
