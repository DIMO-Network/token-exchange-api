package services

import (
	"fmt"

	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/structpb"
)

type CustomClaims struct {
	ContractAddress common.Address         `json:"contract_address"`
	TokenID         string                 `json:"token_id"`
	PrivilegeIDs    []privileges.Privilege `json:"privilege_ids"`
}

type Token struct {
	jwt.RegisteredClaims
	CustomClaims
}

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
		},
	)
}

// Conflicts with the field, whoops.
func (c *CustomClaims) Sub() string {
	return fmt.Sprintf("%s/%s", c.ContractAddress, c.TokenID)
}
