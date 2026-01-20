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

type QueryBody struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type RawResponseSACD struct {
	Permissions string `json:"permissions"`
	Source      string `json:"source"`
}

type Response struct {
	IsOwner     bool
	Permissions *big.Int
	Source      string
}

type RawRespon struct {
	Data *struct {
		Vehicle *Vehicle `json:"vehicle"`
	} `json:"data"`
}

type Vehicle struct {
	Owner common.Address   `json:"owner"`
	SACD  *RawResponseSACD `json:"sacd"`
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

func (c *Client) GetVehicleSACDPermissions(ctx context.Context, tokenID int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	r, err := c.getVehicleSACD(ctx, tokenID, grantee)
	if err != nil {
		return nil, err
	}

	fmt.Printf("ASKED FOR %s\n", permissions.Text(16))

	// What follows recreates the calculations the contract does for getPermissions.
	if r.Owner == grantee {
		fmt.Printf("OWNER\n")

		return permissions, nil
	}
	if r.SACD == nil {
		return nil, errors.New("no SACD with that grantee")
	}

	onChainPerms, err := hexutil.DecodeBig(r.SACD.Permissions)
	if err != nil {
		return nil, err
	}

	fmt.Printf("ONCHAIN %s\n", onChainPerms.Text(16))

	return new(big.Int).And(onChainPerms, permissions), nil
}

func (c *Client) getVehicleSACD(ctx context.Context, tokenID int, grantee common.Address) (*Vehicle, error) {
	qb := QueryBody{
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

	var raw RawRespon
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
