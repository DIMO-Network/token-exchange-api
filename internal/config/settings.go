package config

import "github.com/ethereum/go-ethereum/common"

// Settings contains the application config
type Settings struct {
	Environment              string         `yaml:"ENVIRONMENT"`
	Port                     int            `yaml:"PORT"`
	MonPort                  int            `yaml:"MON_PORT"`
	GRPCPort                 int            `yaml:"GRPC_PORT"`
	EnablePprof              bool           `yaml:"ENABLE_PPROF"`
	LogLevel                 string         `yaml:"LOG_LEVEL"`
	ServiceName              string         `yaml:"SERVICE_NAME"`
	JWKKeySetURL             string         `yaml:"JWT_KEY_SET_URL"`
	BlockchainNodeURL        string         `yaml:"BLOCKCHAIN_NODE_URL"`
	DexGRPCAdddress          string         `yaml:"DEX_GRPC_ADDRESS"`
	UsersAPIGRPCAddress      string         `yaml:"USERS_API_GRPC_ADDRESS"`
	ContractAddressWhitelist string         `yaml:"CONTRACT_ADDRESS_WHITELIST"`
	ContractAddressSacd      common.Address `yaml:"CONTRACT_ADDRESS_SACD"`
	ContractAddressTemplate  common.Address `yaml:"CONTRACT_ADDRESS_TEMPLATE"`
	IdentityURL              string         `yaml:"IDENTITY_URL"`
	IPFSBaseURL              string         `yaml:"IPFS_BASE_URL"`
	IPFSTimeout              string         `yaml:"IPFS_TIMEOUT"`
	DIMORegistryChainID      uint64         `yaml:"DIMO_REGISTRY_CHAIN_ID"`
}
