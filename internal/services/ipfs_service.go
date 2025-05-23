package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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
