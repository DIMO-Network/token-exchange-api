// Package tokenclaims provides a custom JWT token for token-exchange.
package tokenclaims

import (
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/structpb"
)

const GlobalIdentifier = "*"

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
	Tags      []string `json:"tags"`
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

	out := map[string]any{
		"contract_address": hexutil.Encode(c.ContractAddress[:]),
		"token_id":         c.TokenID,
		"privilege_ids":    ap,
	}

	if c.CloudEvents != nil {
		events := []any{}
		for _, evt := range c.CloudEvents.Events {
			ids := []any{}
			for _, id := range evt.IDs {
				ids = append(ids, id)
			}

			events = append(
				events,
				map[string]any{
					"event_type": evt.EventType,
					"source":     evt.Source,
					"ids":        ids,
				},
			)
		}

		out["cloud_events"] = map[string]any{
			"events": events,
		}
	}

	return structpb.NewStruct(out)
}
