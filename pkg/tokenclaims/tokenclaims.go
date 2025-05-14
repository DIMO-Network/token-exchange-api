// Package tokenclaims provides a custom JWT token for token-exchange.
package tokenclaims

import (
	"fmt"

	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/structpb"
)

// CustomClaims is the custom claims for token-exchange related information.
type CustomClaims struct {
	ContractAddress common.Address         `json:"contract_address"`
	TokenID         string                 `json:"token_id"`
	PrivilegeIDs    []privileges.Privilege `json:"privilege_ids"`
	CloudEvents     *CloudEvent            `json:"cloud_event"`
}

type CloudEvent struct {
	Attestations []Attestation
}

type Attestation struct {
	Source *string
	IDs    []string
}

// Token is a JWT token created by token-exchange.
type Token struct {
	jwt.RegisteredClaims
	CustomClaims
}

// Proto converts the CustomClaims to a protobuf struct.
func (c *CustomClaims) Proto() (*structpb.Struct, error) {
	ap := make([]any, len(c.PrivilegeIDs))

	for i := range c.PrivilegeIDs {
		ap[i] = int64(c.PrivilegeIDs[i])
	}

	return structpb.NewStruct(
		map[string]any{
			"contract_address": hexutil.Encode(c.ContractAddress[:]),
			"token_id":         c.TokenID,
			"privilege_ids":    ap,
			"cloud_events":     c.CloudEvents,
		},
	)
}

// Sub returns the subject of the token.
func (c *CustomClaims) Sub() string {
	return fmt.Sprintf("%s/%s", c.ContractAddress, c.TokenID)
}
