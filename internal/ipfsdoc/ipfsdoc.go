package ipfsdoc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
)

// IPFSClient defines the interface for IPFS operations
type IPFSClient interface {
	Fetch(ctx context.Context, cid string) ([]byte, error)
}

// GetValidSacdDoc fetches and validates a SACD document from IPFS.
// It retrieves the document using the provided source identifier, attempts to parse it as JSON,
// and verifies that it has the correct type for a DIMO SACD document.
//
// Parameters:
//   - ctx: The context for the IPFS request, which can be used for cancellation and timeouts
//   - source: The IPFS content identifier (CID) for the SACD document, typically with an "ipfs://" prefix
//   - ipfsClient: The client used to fetch documents from IPFS
//
// Returns:
//   - *cloudevent.RawEvent: A pointer to the parsed raw cloud event if valid
//   - error: An error if the document could not be fetched, parsed, or doesn't have the correct type
func GetValidSacdDoc(ctx context.Context, source string, ipfsClient IPFSClient) (*cloudevent.RawEvent, error) {
	sacdDoc, err := ipfsClient.Fetch(ctx, source)
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
