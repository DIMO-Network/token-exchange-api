package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Client struct {
	HTTP          *http.Client
	QueryEndpoint string
}

type queryRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type sacd struct {
	Permissions string `json:"permissions"`
	Source      string `json:"source"`
}

type queryResponse struct {
	Data *struct {
		Vehicle *vehicle `json:"vehicle"`
	} `json:"data"`
}

type vehicle struct {
	Owner common.Address `json:"owner"`
	SACD  *sacd          `json:"sacd"`
}

var query = `
query ($tokenId: Int!, $grantee: Address!) {
	vehicle(tokenId: $tokenId) {
		owner
		sacd(grantee: $grantee) {
			permissions
			source
		}
	}
}
`

// GetVehicleSACDSource returns the URI of the active SACD document for the given vehicle NFT and grantee.
// If there is no active SACD set this will return an error, even if grantee is the owner of the vehicle.
func (c *Client) GetVehicleSACDSource(ctx context.Context, tokenID int, grantee common.Address) (string, error) {
	r, err := c.getVehicleSACD(ctx, tokenID, grantee)
	if err != nil {
		return "", err
	}
	if r.SACD == nil {
		return "", errors.New("no SACD with that grantee")
	}
	return r.SACD.Source, nil
}

// GetVehicleSACDPermissions returns the intersection of the provided permissions and the permissions the grantee has on
// the given vehicle NFT. If grantee is the owner of the vehicle NFT then he will have all permissions.
func (c *Client) GetVehicleSACDPermissions(ctx context.Context, tokenID int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	r, err := c.getVehicleSACD(ctx, tokenID, grantee)
	if err != nil {
		return nil, err
	}

	// What follows recreates the calculations the contract does for getPermissions.
	if r.Owner == grantee {
		return permissions, nil
	}
	if r.SACD == nil {
		return nil, errors.New("no SACD with that grantee")
	}

	onChainPerms, err := hexutil.DecodeBig(r.SACD.Permissions)
	if err != nil {
		return nil, err
	}

	return new(big.Int).And(onChainPerms, permissions), nil
}

func (c *Client) getVehicleSACD(ctx context.Context, tokenID int, grantee common.Address) (*vehicle, error) {
	qb := queryRequest{
		Query: query,
		Variables: map[string]any{
			"tokenId": tokenID,
			"grantee": grantee,
		},
	}

	b, err := json.Marshal(qb)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.QueryEndpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	bb, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", res.StatusCode)
	}

	var raw queryResponse
	err = json.Unmarshal(bb, &raw)
	if err != nil {
		return nil, err
	}

	// TODO(elffjs): Check errors instead.
	if raw.Data == nil {
		return nil, errors.New("vehicle not found")
	}

	return raw.Data.Vehicle, nil
}
