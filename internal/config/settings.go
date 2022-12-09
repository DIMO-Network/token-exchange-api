package config

// Settings contains the application config
type Settings struct {
	Environment         string `yaml:"ENVIRONMENT"`
	Port                string `yaml:"PORT"`
	MonPort             string `yaml:"MON_PORT"`
	LogLevel            string `yaml:"LOG_LEVEL"`
	ServiceName         string `yaml:"SERVICE_NAME"`
	JWKKeySetURL        string `yaml:"JWT_KEY_SET_URL"`
	BlockchainNodeURL   string `yaml:"BLOCKCHAIN_NODE_URL"`
	VehicleNFTAddress   string `yaml:"VEHICLE_NFT_ADDRESS"`
	DexGRPCAdddress     string `yaml:"DEX_GRPC_ADDRESS"`
	UsersAPIGRPCAddress string `yaml:"USERS_API_GRPC_ADDRESS"`
}
