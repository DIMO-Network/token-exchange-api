package config

// Settings contains the application config
type Settings struct {
	Environment  string `yaml:"ENVIRONMENT"`
	Port         string `yaml:"PORT"`
	LogLevel     string `yaml:"LOG_LEVEL"`
	ServiceName  string `yaml:"SERVICE_NAME"`
	JwtKeySetURL string `yaml:"JWT_KEY_SET_URL"`
	KMSKeyID     string `yaml:"KMS_KEY_ID"`
	AWSRegion    string `yaml:"AWS_REGION"`
}
