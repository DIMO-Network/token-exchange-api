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

var GlobalAttestationPermission = "GLOBAL_ATTESTATION_PERMISSION"

// CustomClaims is the custom claims for token-exchange related information.
type CustomClaims struct {
	ContractAddress common.Address         `json:"contract_address"`
	TokenID         string                 `json:"token_id"`
	PrivilegeIDs    []privileges.Privilege `json:"privilege_ids"`
	CloudEvents     *CloudEvents           `json:"cloud_event"`
}

type CloudEvents struct {
	Events []Event `json:"events"`
}

type Event struct {
	EventType string   `json:"eventType"`
	Source    *string  `json:"source"`
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

	ces := make((map[string]map[string]any))
	for _, evt := range c.CloudEvents.Events {
		if _, ok := ces[evt.EventType]; !ok {
			ces[evt.EventType] = map[string]any{}
		}

		if _, ok := ces[evt.EventType][*evt.Source]; !ok {
			// NOTE: this will overwrite, to avoid that, I think that prior
			// to this point we should return an error if someone is passing
			// multiple cloud event requests with the same source, directing them that
			// all ids for the same source to be passed in the same event request
			ces[evt.EventType][*evt.Source] = evt.IDs
		}
	}

	return structpb.NewStruct(
		map[string]any{
			"contract_address": hexutil.Encode(c.ContractAddress[:]),
			"token_id":         c.TokenID,
			"privilege_ids":    ap,
			"cloud_events":     ces,
		},
	)
}

// Sub returns the subject of the token.
func (c *CustomClaims) Sub() string {
	return fmt.Sprintf("%s/%s", c.ContractAddress, c.TokenID)
}
