// Package tokenclaims provides a custom JWT token for token-exchange.
package tokenclaims

import (
	"fmt"

	"github.com/DIMO-Network/shared/pkg/privileges"
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
	CloudEvents     *CloudEvents           `json:"cloud_events"`
}

type CloudEvents struct {
	Events []Event `json:"events"`
}

type Event struct {
	EventType string   `json:"event_type"`
	Source    string   `json:"source"`
	IDs       []string `json:"ids"`
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

	ces := []any{}
	if c.CloudEvents != nil {
		for _, evt := range c.CloudEvents.Events {
			ids := []any{}
			for _, id := range evt.IDs {
				ids = append(ids, id)
			}

			e, err := structpb.NewStruct(map[string]any{
				"event_type": evt.EventType,
				"source":     evt.Source,
				"ids":        ids,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create pb struct from cloudevent: %w", err)
			}

			ces = append(ces, e.AsMap())
		}
	}

	return structpb.NewStruct(map[string]any{
		"contract_address": hexutil.Encode(c.ContractAddress[:]),
		"token_id":         c.TokenID,
		"privilege_ids":    ap,
		"cloud_events":     ces,
	})
}

// Sub returns the subject of the token.
func (c *CustomClaims) Sub() string {
	return fmt.Sprintf("%s/%s", c.ContractAddress, c.TokenID)
}
