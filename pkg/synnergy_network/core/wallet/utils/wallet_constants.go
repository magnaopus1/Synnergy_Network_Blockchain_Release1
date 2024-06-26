package utils

// Wallet Constants
const (
	// Key generation constants
	KeyType               = "ECDSA"
	KeyCurve              = "P256"
	SignatureAlgorithm    = "SHA256"
	KeyDerivationFunction = "scrypt"
	KeyDerivationSaltSize = 16
	KeyDerivationN        = 16384
	KeyDerivationR        = 8
	KeyDerivationP        = 1

	// AES encryption constants
	AESKeySize       = 32
	AESNonceSize     = 12
	AESGCMTagSize    = 16
	AESGCMStandard   = "AES-GCM"
	EncryptionScheme = "aes-256-gcm"

	// Mnemonic phrase constants
	MnemonicWordCount    = 12
	MnemonicEntropySize  = 128
	MnemonicLanguage     = "english"
	MnemonicPassphrase   = "BIP39 Passphrase"
	MnemonicSaltPrefix   = "mnemonic"
	MnemonicDerivationPath = "m/44'/60'/0'/0/0"

	// Blockchain constants
	DefaultGasLimit         = 21000
	DefaultGasPrice         = 1e9
	BlockConfirmationDepth  = 6
	TransactionTimeout      = 10 // minutes
	MaxTransactionRetries   = 3
	DefaultTransactionFee   = 0.001 // Synthron coin

	// Notifications
	NotificationTransactionSent    = "Transaction Sent"
	NotificationTransactionReceived = "Transaction Received"
	NotificationBalanceUpdated     = "Balance Updated"

	// Wallet freezing
	WalletFreezeThresholdAmount = 1000000 // Threshold amount in Synthron coin
	WalletFreezeDuration        = 24 * 60 * 60 // Duration in seconds

	// Wallet recovery
	RecoveryTokenValidity       = 24 * 60 * 60 // Validity duration in seconds
	RecoveryBackupFrequency     = 7 * 24 * 60 * 60 // Weekly backup frequency in seconds
	RecoveryMultiFactorAuth     = true // Enable multi-factor authentication for recovery

	// Address alias system
	AddressAliasMaxLength       = 64
	AddressAliasMinLength       = 3
	AddressAliasCharacters      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

	// Exchange integration
	ExchangeAPIBaseURL          = "https://api.exchange.synnergy.network"
	ExchangeOrderBookDepth      = 50
	ExchangeTransactionTimeout  = 30 // seconds

	// User Interface
	DefaultTheme                = "dark"
	DefaultFontSize             = 14
	ARIntegrationEnabled        = true
	VoiceCommandEnabled         = true

	// Security
	HardwareSecurityModule      = true
	QuantumResistanceEnabled    = true
	ZeroKnowledgeProofsEnabled  = true

	// Miscellaneous
	TransactionIDLength         = 64
	MaxWalletsPerUser           = 10
	MaxKeysPerWallet            = 100
	MaxConcurrentTransactions   = 5
)

// Function to get key derivation parameters
func GetKeyDerivationParams() (int, int, int) {
	return KeyDerivationN, KeyDerivationR, KeyDerivationP
}

// Function to get AES encryption parameters
func GetAESEncryptionParams() (int, int, int) {
	return AESKeySize, AESNonceSize, AESGCMTagSize
}

// Function to get default mnemonic settings
func GetDefaultMnemonicSettings() (int, string) {
	return MnemonicWordCount, MnemonicLanguage
}

// Function to get default gas settings
func GetDefaultGasSettings() (int, int) {
	return DefaultGasLimit, DefaultGasPrice
}

// Function to get default transaction settings
func GetDefaultTransactionSettings() (int, float64) {
	return BlockConfirmationDepth, DefaultTransactionFee
}
