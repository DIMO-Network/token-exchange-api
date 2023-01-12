package services

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/protobuf/types/known/structpb"
)

type CustomClaims struct {
	ContractAddress common.Address `json:"contract_address"`
	TokenID         string         `json:"token_id"`
	PrivilegeIDs    []int64        `json:"privilege_ids"`
}

func (c *CustomClaims) Proto() (*structpb.Struct, error) {
	ap := make([]any, len(c.PrivilegeIDs))

	for i := range c.PrivilegeIDs {
		ap[i] = c.PrivilegeIDs[i]
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

func GetJWTTokenClaims(c *fiber.Ctx) map[string]any {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	return claims
}
