package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"

	"github.com/DIMO-Network/token-exchange-api/internal/services/identity"
	"github.com/ethereum/go-ethereum/common"
)

func main() {
	tokenID := flag.Int("token-id", 0, "Vehicle token ID")
	grantee := flag.String("grantee", "", "Grantee address")
	permissions := flag.String("permissions", "0", "Permissions value (binary, e.g. 1100)")
	flag.Parse()

	if *tokenID == 0 {
		fmt.Println("Error: token-id is required")
		flag.Usage()
		os.Exit(1)
	}

	if *grantee == "" {
		fmt.Println("Error: grantee address is required")
		flag.Usage()
		os.Exit(1)
	}

	if !common.IsHexAddress(*grantee) {
		fmt.Printf("Error: invalid Ethereum address: %s\n", *grantee)
		os.Exit(1)
	}

	permsBigInt := new(big.Int)
	_, ok := permsBigInt.SetString(*permissions, 2)
	if !ok {
		fmt.Printf("Error: invalid binary permissions value: %s\n", *permissions)
		os.Exit(1)
	}

	client := &identity.Client{
		HTTP:          &http.Client{},
		QueryEndpoint: "https://identity-api.dimo.zone/query",
	}

	ctx := context.Background()
	granteeAddr := common.HexToAddress(*grantee)

	fmt.Println("=== GetVehicleSACDSource ===")
	source, err := client.GetVehicleSACDSource(ctx, *tokenID, granteeAddr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Source: %s\n", source)
	}

	fmt.Println("\n=== GetVehicleSACDPermissions ===")
	resultPerms, err := client.GetVehicleSACDPermissions(ctx, *tokenID, granteeAddr, permsBigInt)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Calculated Permissions: 0x%s\n", resultPerms.Text(16))
	}
}
