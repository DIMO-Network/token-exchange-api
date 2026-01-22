package sacdproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"slices"
	"time"

	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Proxy struct {
	Contract               *sacd.Sacd
	ContractAddressVehicle common.Address
	HTTP                   *http.Client
	QueryEndpoint          string
}

func (p *Proxy) AccountPermissionRecords(opts *bind.CallOpts, grantor common.Address, grantee common.Address) (sacd.ISacdPermissionRecord, error) {
	return p.Contract.AccountPermissionRecords(opts, grantor, grantee)
}

var blankResp = sacd.ISacdPermissionRecord{
	Permissions: big.NewInt(0),
	Expiration:  big.NewInt(0),
	TemplateId:  big.NewInt(0),
}

// CurrentPermissionRecord returns the current "permission record" for the given asset. If no such record is found then
// zero values are returned for all fields. In this case it may not be that the asset exists.
func (p *Proxy) CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address) (sacd.ISacdPermissionRecord, error) {
	if asset == p.ContractAddressVehicle {
		v, err := p.getVehicleSACD(opts.Context, tokenID, grantee)
		if err != nil {
			if errors.Is(err, errVehicleNotFound) {
				return blankResp, nil
			}
			return blankResp, err
		}

		if v.SACD == nil {
			return blankResp, nil
		}

		perms, err := hexutil.DecodeBig(v.SACD.Permissions)
		if err != nil {
			return blankResp, fmt.Errorf("couldn't parse permissions hex: %w", err)
		}

		expire := big.NewInt(v.SACD.ExpiresAt.Unix())

		var templateID *big.Int
		if v.SACD.Template != nil {
			templateID = v.SACD.Template.TokenID
		} else {
			templateID = big.NewInt(0)
		}

		return sacd.ISacdPermissionRecord{
			Permissions: perms,
			Expiration:  expire,
			Source:      v.SACD.Source,
			TemplateId:  templateID,
		}, nil
	}

	return p.Contract.CurrentPermissionRecord(opts, asset, tokenID, grantee)
}

func (p *Proxy) GetAccountPermissions(opts *bind.CallOpts, grantor common.Address, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	return p.Contract.GetAccountPermissions(opts, grantor, grantee, permissions)
}

// GetPermissions computes the intersection of the provided permissions on the asset and the permissions that
// the grantee has. If the grantee is the owner of the asset then he will have access to everything.
func (p *Proxy) GetPermissions(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	if asset == p.ContractAddressVehicle {
		v, err := p.getVehicleSACD(opts.Context, tokenID, grantee)
		if err != nil {
			if errors.Is(err, errVehicleNotFound) {
				return big.NewInt(0), nil
			}
			return nil, err
		}

		if v.Owner == grantee {
			return permissions, nil
		}

		if v.SACD == nil {
			return big.NewInt(0), nil
		}

		identPerms, err := hexutil.DecodeBig(v.SACD.Permissions)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse permissions hex: %w", err)
		}

		return new(big.Int).And(identPerms, permissions), nil
	}

	return p.Contract.GetPermissions(opts, asset, tokenID, grantee, permissions)
}

// convertTokenID makes sure that the given tokenID is usable in the Identity API, and converts it
// to an int for ease of use.
func convertTokenID(tokenID *big.Int) (int, error) {
	if tokenID == nil {
		return 0, errors.New("nil pointer")
	}

	if tokenID.Sign() <= 0 {
		return 0, errors.New("value not positive")
	}

	if !tokenID.IsInt64() {
		return 0, errors.New("outside of int64 range")
	}

	tokenIDInt64 := tokenID.Int64()

	// GraphQL Int is an int32.
	if tokenIDInt64 > math.MaxInt32 {
		return 0, errors.New("outside of int32 range")
	}

	return int(tokenIDInt64), nil
}

func (p *Proxy) getVehicleSACD(ctx context.Context, tokenID *big.Int, grantee common.Address) (*vehicle, error) {
	tokenIDParsed, err := convertTokenID(tokenID)
	if err != nil {
		return nil, err
	}

	qb := queryRequest{
		Query: query,
		Variables: map[string]any{
			"tokenId": tokenIDParsed,
			"grantee": grantee,
		},
	}

	b, err := json.Marshal(qb)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.QueryEndpoint, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("couldn't create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := p.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	bb, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}

	var raw queryResponse
	err = json.Unmarshal(bb, &raw)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal GraphQL response: %w", err)
	}

	if len(raw.Errors) != 0 {
		gqlErr := raw.Errors[0]
		if slices.Equal(gqlErr.Path, []string{"vehicle"}) && gqlErr.Extensions.Code == "NOT_FOUND" {
			return nil, errVehicleNotFound
		}

		return nil, fmt.Errorf("returned %d GraphQL errors, first is %q", len(raw.Errors), raw.Errors[0].Message)
	}

	return &raw.Data.Vehicle, nil
}

var errVehicleNotFound = errors.New("no vehicle with that token id")

type queryRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type vehicleSacd struct {
	Permissions string        `json:"permissions"`
	Source      string        `json:"source"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	Template    *sacdTemplate `json:"template"`
}

type queryResponse struct {
	Data struct {
		Vehicle vehicle `json:"vehicle"`
	} `json:"data"`
	Errors []struct {
		Message    string   `json:"message"`
		Path       []string `json:"path"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

type sacdTemplate struct {
	TokenID *big.Int `json:"tokenId"`
}

type vehicle struct {
	Owner common.Address `json:"owner"`
	SACD  *vehicleSacd   `json:"sacd"`
}

var query = `
query ($tokenId: Int!, $grantee: Address!) {
	vehicle(tokenId: $tokenId) {
		owner
		sacd(grantee: $grantee) {
			permissions
			source
			expiresAt
			template {
				tokenId
			}
		}
	}
}
`
