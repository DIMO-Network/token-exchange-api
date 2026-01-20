package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/DIMO-Network/token-exchange-api/internal/services/identity"
	"github.com/ethereum/go-ethereum/common"
)

func main() {
	tokenID := flag.Int("token-id", 0, "Vehicle token ID")
	grantee := flag.String("grantee", "", "Grantee address")
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

	client := &identity.Client{
		HTTP: &http.Client{},
	}

	ctx := context.Background()
	resp, err := client.GetVehicleSACD(ctx, *tokenID, common.HexToAddress(*grantee))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Success!\n")
	fmt.Printf("Permissions: 0x%s\n", resp.Permissions.Text(16))
	fmt.Printf("Source: %s\n", resp.Source)
}
