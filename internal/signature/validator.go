package signature

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DIMO-Network/token-exchange-api/internal/contracts/erc1271"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var erc1271MagicValue = [4]byte{0x16, 0x26, 0xba, 0x7e}

type Erc1271Interface interface {
	IsValidSignature(opts *bind.CallOpts, hash [32]byte, signature []byte) ([4]byte, error)
}

type erc1271Mgr interface {
	NewErc1271(address common.Address, backend bind.ContractBackend) (Erc1271Interface, error)
}

type defaultErc1271Factory struct{}

func (f *defaultErc1271Factory) NewErc1271(address common.Address, backend bind.ContractBackend) (Erc1271Interface, error) {
	return erc1271.NewErc1271(address, backend)
}

// Validator handles signature validation for both EOA and contract accounts
type Validator struct {
	backend bind.ContractBackend
	// I don't like this, but it's the only way to get the mock to work.
	erc1271Mgr erc1271Mgr
}

// NewValidator creates a new signature validator
func NewValidator(backend bind.ContractBackend) *Validator {
	return &Validator{
		backend:    backend,
		erc1271Mgr: &defaultErc1271Factory{},
	}
}

// ValidateSignature validates a signature against an Ethereum address
// It first tries EOA signature recovery, then falls back to ERC-1271 if that fails
func (v *Validator) ValidateSignature(ctx context.Context, payload json.RawMessage, signature string, ethAddr common.Address) (bool, error) {
	if signature == "" {
		return false, errors.New("empty signature")
	}
	hexSignature := common.FromHex(signature)

	hashWithPrfx := accounts.TextHash(payload)
	err := ValidEOASignature(hashWithPrfx, hexSignature, ethAddr)
	if err == nil {
		return true, nil
	}
	errs := fmt.Errorf("failed to recover signer: %w", err)

	// Fall back to ERC-1271 validation
	opts := &bind.CallOpts{
		Context: ctx,
	}
	contract, err := v.erc1271Mgr.NewErc1271(ethAddr, v.backend)
	if err != nil {
		return false, fmt.Errorf("failed to connect to address: %s: %w", ethAddr.Hex(), err)
	}

	result, err := contract.IsValidSignature(opts, common.BytesToHash(hashWithPrfx), hexSignature)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("erc1271 call failed: %w", err))
		return false, errs
	}
	return result == erc1271MagicValue, nil
}

// ValidEOASignature validates a signature using the ECDSA recovery method
func ValidEOASignature(hashWithPrfx []byte, signature []byte, ethAddr common.Address) error {
	if len(signature) != 65 {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	sigCopy[64] -= 27
	if sigCopy[64] != 0 && sigCopy[64] != 1 {
		return fmt.Errorf("invalid v byte: %d; accepted values 27 or 28", signature[64])
	}
	recoveredPubKey, err := crypto.SigToPub(hashWithPrfx, sigCopy)
	if err != nil {
		return fmt.Errorf("failed to determine public key from signature: %w", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)
	if recoveredAddr != ethAddr {
		return fmt.Errorf("invalid signature: %s", recoveredAddr.Hex())
	}
	return nil
}
