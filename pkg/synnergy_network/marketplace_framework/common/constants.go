package common

const (
	// Network Constants
	DefaultNetworkPort           = 8080
	DefaultNetworkProtocol       = "tcp"
	DefaultNetworkMaxConnections = 1000

	// Security Constants
	DefaultEncryptionMethod      = "AES_Scrypt"
	DefaultSecretKey             = "mysecretkey123456" // This should be changed and securely stored in a real application
	ScryptN                      = 1 << 15
	ScryptR                      = 8
	ScryptP                      = 1
	Argon2Time                   = 1
	Argon2Memory                 = 64 * 1024
	Argon2Threads                = 4
	Argon2KeyLength              = 32

	// Database Constants
	DefaultDBType                = "postgres"
	DefaultDBHost                = "localhost"
	DefaultDBPort                = 5432
	DefaultDBUsername            = "user"
	DefaultDBPassword            = "password"
	DefaultDBName                = "synnergy_network"

	// API Constants
	DefaultAPIBaseURL            = "http://localhost:8080/api"
	DefaultAPITimeout            = 30 // seconds

	// Logging Constants
	DefaultLogLevel              = "INFO"
	DefaultLogFilePath           = "logs/synnergy_network.log"

	// Consensus Constants
	DefaultConsensusAlgorithm    = "PoW"
	DefaultConsensusDifficulty   = 4

	// Error Messages
	ErrorInvalidConfig           = "Invalid configuration"
	ErrorOpeningConfigFile       = "Error opening config file"
	ErrorReadingConfigFile       = "Error reading config file"
	ErrorUnmarshalingConfigFile  = "Error unmarshaling config file"
	ErrorMarshalingConfig        = "Error marshaling config"
	ErrorWritingConfigFile       = "Error writing config file"
	ErrorNoConfigToSave          = "No configuration to save"
	ErrorConfigNotLoaded         = "Configuration not loaded"
	ErrorInvalidNetworkPort      = "Invalid network port"
	ErrorSecretKeyRequired       = "Security secret key is required"
	ErrorInvalidDBConfig         = "Invalid database configuration"
	ErrorInvalidAPIConfig        = "Invalid API configuration"
	ErrorInvalidLogConfig        = "Invalid logging configuration"
	ErrorInvalidConsensusConfig  = "Invalid consensus configuration"

	// Encryption Constants
	AESKeySize                   = 32 // AES-256
	AESBlockSize                 = 16
	SaltSize                     = 16
)

// Securely store secret keys and sensitive information using environment variables
const (
	EnvSecretKey                 = "SYNNERGY_SECRET_KEY"
	EnvDBPassword                = "SYNNERGY_DB_PASSWORD"
)
