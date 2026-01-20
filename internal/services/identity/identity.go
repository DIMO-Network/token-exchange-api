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
	HTTP *http.Client
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
	Permissions *big.Int
	Source      string
}

type RawRespon struct {
	Data *struct {
		Vehicle *Vehicle `json:"vehicle"`
	} `json:"data"`
}

type Vehicle struct {
	SACD *RawResponseSACD `json:"sacd"`
}

var query = `
query ($tokenId: Int!, $grantee: Address!) {
	vehicle(tokenId: $tokenId) {
		sacd(grantee: $grantee) {
			permissions
			source
		}
	}
}
`

func (c *Client) GetVehicleSACD(ctx context.Context, tokenID int, grantee common.Address) (*Response, error) {
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

	req, err := http.NewRequestWithContext(ctx, "POST", "https://identity-api.dimo.zone/query", bytes.NewReader(b))
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

	fmt.Println(string(bb))

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

	if raw.Data.Vehicle.SACD == nil {
		return nil, errors.New("no SACD found")
	}
	p, err := hexutil.DecodeBig(raw.Data.Vehicle.SACD.Permissions)
	if err != nil {
		return nil, err
	}
	return &Response{
		Permissions: p,
		Source:      raw.Data.Vehicle.SACD.Source,
	}, nil

}
