package main

import (
	"fmt"

	"github.com/DIMO-Network/cloudevent"
)

func main() {
	fmt.Println("Hello, 世界")

	decoded1, err := cloudevent.DecodeERC721DID("did:erc721:1:0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(decoded1)
	}
}
