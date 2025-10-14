// Package tokenclaims provides a custom JWT token for token-exchange.
package tokenclaims

import (
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/DIMO-Network/token-exchange-api/internal/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/structpb"
)

// GlobalIdentifier is the global identifier that represents all strings.
const GlobalIdentifier = models.GlobalIdentifier

// CustomClaims is the custom claims for token-exchange related information.
type CustomClaims struct {
	// Asset is the asset DID of the asset that permissions are being requested for currently either did:erc721 or did:ethr
	Asset       string       `json:"asset"`
	Permissions []string     `json:"permissions"`
	CloudEvents *CloudEvents `json:"cloud_events"`

	// Deprecated: Use Asset instead.
	ContractAddress common.Address `json:"contract_address"`
	// Deprecated: Use Asset instead.
	TokenID string `json:"token_id"`
	// Deprecated: Use Permissions instead.
	PrivilegeIDs []privileges.Privilege `json:"privilege_ids"`
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
	privIds := make([]any, len(c.PrivilegeIDs))
	permNames := make([]any, len(c.Permissions))
	for i, perm := range c.Permissions {
		privIds[i] = models.PrivilegeNameToID[perm]
		permNames[i] = perm
	}

	out := map[string]any{
		"asset":       c.Asset,
		"permissions": permNames,

		// TODO: Remove these fields once we switch over our internal services.
		"contract_address": hexutil.Encode(c.ContractAddress[:]),
		"token_id":         c.TokenID,
		"privilege_ids":    privIds,
	}

	if c.CloudEvents != nil {
		events := []any{}
		for _, evt := range c.CloudEvents.Events {
			ids := []any{}
			for _, id := range evt.IDs {
				ids = append(ids, id)
			}

			tags := []any{}
			for _, tag := range evt.Tags {
				tags = append(tags, tag)
			}

			events = append(
				events,
				map[string]any{
					"event_type": evt.EventType,
					"source":     evt.Source,
					"ids":        ids,
					"tags":       tags,
				},
			)
		}

		out["cloud_events"] = map[string]any{
			"events": events,
		}
	}

	return structpb.NewStruct(out)
}
