package config

// Settings contains the application config
type Settings struct {
	Environment              string `yaml:"ENVIRONMENT"`
	Port                     string `yaml:"PORT"`
	MonPort                  string `yaml:"MON_PORT"`
	LogLevel                 string `yaml:"LOG_LEVEL"`
	ServiceName              string `yaml:"SERVICE_NAME"`
	JWKKeySetURL             string `yaml:"JWT_KEY_SET_URL"`
	BlockchainNodeURL        string `yaml:"BLOCKCHAIN_NODE_URL"`
	DexGRPCAdddress          string `yaml:"DEX_GRPC_ADDRESS"`
	UsersAPIGRPCAddress      string `yaml:"USERS_API_GRPC_ADDRESS"`
	ContractAddressWhitelist string `yaml:"CONTRACT_ADDRESS_WHITELIST"`
	ContractAddressSacd      string `yaml:"CONTRACT_ADDRESS_SACD"`
	IdentityURL              string `yaml:"IDENTITY_URL"`
	IPFSBaseURL              string `yaml:"IPFS_BASE_URL"`
	IPFSTimeout              string `yaml:"IPFS_TIMEOUT"`
}
