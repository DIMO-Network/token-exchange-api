package config

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Settings contains the application config
type Settings struct {
	Environment                 string         `yaml:"ENVIRONMENT"`
	Port                        int            `yaml:"PORT"`
	MonPort                     int            `yaml:"MON_PORT"`
	GRPCPort                    int            `yaml:"GRPC_PORT"`
	EnablePprof                 bool           `yaml:"ENABLE_PPROF"`
	LogLevel                    string         `yaml:"LOG_LEVEL"`
	ServiceName                 string         `yaml:"SERVICE_NAME"`
	JWKKeySetURL                string         `yaml:"JWT_KEY_SET_URL"`
	BlockchainNodeURL           string         `yaml:"BLOCKCHAIN_NODE_URL"`
	DexGRPCAdddress             string         `yaml:"DEX_GRPC_ADDRESS"`
	ContractAddressSacd         common.Address `yaml:"CONTRACT_ADDRESS_SACD"`
	ContractAddressTemplate     common.Address `yaml:"CONTRACT_ADDRESS_TEMPLATE"`
	ContractAddressManufacturer common.Address `yaml:"CONTRACT_ADDRESS_MANUFACTURER"`
	ContractAddressVehicle      common.Address `yaml:"CONTRACT_ADDRESS_VEHICLE"`
	IdentityURL                 string         `yaml:"IDENTITY_URL"`
	IPFSBaseURL                 string         `yaml:"IPFS_BASE_URL"`
	IPFSTimeout                 string         `yaml:"IPFS_TIMEOUT"`
	DIMORegistryChainID         uint64         `yaml:"DIMO_REGISTRY_CHAIN_ID"`
	// SignerCheckMode is enforce (default), log or off.
	SignerCheckMode string `yaml:"SIGNER_CHECK_MODE"`
	// SignerClaimRequiredAfter, a Unix time, refuses license tokens issued after it without
	// signer_address. Zero (the default) disables that rule.
	SignerClaimRequiredAfter int64 `yaml:"SIGNER_CLAIM_REQUIRED_AFTER"`
}

// SignerClaimCutoff is SIGNER_CLAIM_REQUIRED_AFTER as a time; the zero time when unset.
func (s *Settings) SignerClaimCutoff() time.Time {
	if s.SignerClaimRequiredAfter <= 0 {
		return time.Time{}
	}
	return time.Unix(s.SignerClaimRequiredAfter, 0)
}
