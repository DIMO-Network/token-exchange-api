package controllers

import (
	"fmt"
	"math/big"

	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/common"
)

// validateAssetDID verifies that the provided DID matches the NFT contract address
// and token ID specified in the permission token request.
//
// Parameters:
//   - did: The decentralized identifier string to validate, typically in the format "did:nft:..."
//   - req: The permission token request containing the NFT contract address and token ID to match against
//
// Returns:
//   - bool: true if the DID is valid and matches the request parameters, false otherwise
//   - error: An error describing why validation failed, or nil if validation succeeded
func (t *TokenExchangeController) validateAssetDID(did string, req *PermissionTokenRequest) (bool, error) {
	decodedDID, err := cloudevent.DecodeNFTDID(did)
	if err != nil {
		return false, fmt.Errorf("failed to decode DID: %w", err)
	}

	requestNFTAddr := common.HexToAddress(req.NFTContractAddress)

	if decodedDID.ContractAddress != requestNFTAddr {
		return false, fmt.Errorf("DID contract address %s does not match request contract address %s",
			decodedDID.ContractAddress.Hex(), requestNFTAddr.Hex())
	}

	if int64(decodedDID.TokenID) != req.TokenID {
		return false, fmt.Errorf("DID token ID %d does not match request token ID %d",
			decodedDID.TokenID, req.TokenID)
	}

	// If we get here, the DID is valid for the given request
	return true, nil
}

func intArrayTo2BitArray(indices []int64, length int) (*big.Int, error) {
	mask := big.NewInt(0)

	for _, index := range indices {
		if index < 0 || index >= int64(length) {
			return big.NewInt(0), fmt.Errorf("invalid index %d. These must be non-negative and less than %d", index, length)
		}
		mask.SetBit(mask, int(index*2), 1)
		mask.SetBit(mask, int(index*2+1), 1)
	}

	return mask, nil
}
