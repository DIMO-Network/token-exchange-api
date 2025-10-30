package models

import (
	"fmt"
	"math/big"

	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/common"
)

// AssetDID represents either an ERC721 or Ethr DID
type AssetDID interface {
	String() string
	GetChainID() uint64
	GetContractAddress() common.Address
	IsAccountLevel() bool
	GetTokenID() *big.Int
}

// ERC721Asset wraps cloudevent.ERC721DID to implement AssetDID
type ERC721Asset struct {
	cloudevent.ERC721DID
}

func (e ERC721Asset) IsAccountLevel() bool {
	return false
}

func (e ERC721Asset) GetChainID() uint64 {
	return e.ChainID
}

func (e ERC721Asset) GetContractAddress() common.Address {
	return e.ContractAddress
}

func (e ERC721Asset) GetTokenID() *big.Int {
	return e.TokenID
}

// EthrAsset wraps cloudevent.EthrDID to implement AssetDID
type EthrAsset struct {
	cloudevent.EthrDID
}

func (e EthrAsset) IsAccountLevel() bool {
	return true
}

func (e EthrAsset) GetChainID() uint64 {
	return e.ChainID
}

func (e EthrAsset) GetContractAddress() common.Address {
	return e.ContractAddress
}

func (e EthrAsset) GetTokenID() *big.Int {
	return nil
}

// Shared helper to decode string asset DID to correct AssetDID implementation
func DecodeAssetDID(asset string) (AssetDID, error) {
	erc721DID, err := cloudevent.DecodeERC721DID(asset)
	if err == nil {
		return ERC721Asset{ERC721DID: erc721DID}, nil
	}
	ethrDID, err := cloudevent.DecodeEthrDID(asset)
	if err == nil {
		return EthrAsset{EthrDID: ethrDID}, nil
	}
	return nil, fmt.Errorf("invalid asset DID %q: %w", asset, err)
}
