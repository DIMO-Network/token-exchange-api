package config

// Settings contains the application config
type Settings struct {
	Environment       string `yaml:"ENVIRONMENT"`
	Port              string `yaml:"PORT"`
	LogLevel          string `yaml:"LOG_LEVEL"`
	ServiceName       string `yaml:"SERVICE_NAME"`
	JwtKeySetURL      string `yaml:"JWT_KEY_SET_URL"`
	BlockchainNodeUrl string `yaml:"BLOCKCHAIN_NODE_URL"`
	VehicleNFTAddress string `yaml:"VEHICLE_NFT_ADDRESS"`
}
