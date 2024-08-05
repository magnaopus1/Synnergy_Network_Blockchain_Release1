package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

// CustomError defines a struct for custom error handling
type CustomError struct {
	Timestamp time.Time
	Code      int
	Message   string
	Details   string
}

// Error codes
const (
	ERR_INVALID_INPUT         = 1001
	ERR_DATABASE_CONNECTION   = 1002
	ERR_TRANSACTION_FAILED    = 1003
	ERR_UNAUTHORIZED_ACCESS   = 1004
	ERR_INSUFFICIENT_BALANCE  = 1005
	ERR_NETWORK_ISSUE         = 1006
	ERR_BLOCKCHAIN_FORK       = 1007
	ERR_SMART_CONTRACT_ERROR  = 1008
	ERR_ENCRYPTION_FAILURE    = 1009
	ERR_DECRYPTION_FAILURE    = 1010
	ERR_WALLET_RECOVERY       = 1011
	ERR_WALLET_FREEZE         = 1012
)

// Error method to implement the error interface
func (e *CustomError) Error() string {
	return fmt.Sprintf("[%s] Error %d: %s - %s", e.Timestamp.Format(time.RFC3339), e.Code, e.Message, e.Details)
}

// LogError logs the error to a file and standard output
func LogError(err error) {
	logFile, logErr := os.OpenFile("wallet_errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if logErr != nil {
		log.Printf("Failed to open log file: %v", logErr)
		return
	}
	defer logFile.Close()

	logger := log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Println(err)

	fmt.Println(err)
}

// NewCustomError creates a new custom error
func NewCustomError(code int, message string, details string) *CustomError {
	return &CustomError{
		Timestamp: time.Now(),
		Code:      code,
		Message:   message,
		Details:   details,
	}
}

// HandleError processes the error based on its type and context
func HandleError(err error) {
	switch e := err.(type) {
	case *CustomError:
		LogError(e)
		// Additional handling based on error code
		switch e.Code {
		case ERR_DATABASE_CONNECTION:
			// Attempt to reconnect or alert the administrator
		case ERR_TRANSACTION_FAILED:
			// Rollback transaction and notify user
		case ERR_UNAUTHORIZED_ACCESS:
			// Log the attempt and possibly alert security
		case ERR_INSUFFICIENT_BALANCE:
			// Notify user to check their balance
		case ERR_NETWORK_ISSUE:
			// Retry the network operation or alert network admin
		case ERR_BLOCKCHAIN_FORK:
			// Handle fork resolution
		case ERR_SMART_CONTRACT_ERROR:
			// Log contract error and alert developers
		case ERR_ENCRYPTION_FAILURE, ERR_DECRYPTION_FAILURE:
			// Alert about potential security issue
		case ERR_WALLET_RECOVERY:
			// Guide user through recovery process
		case ERR_WALLET_FREEZE:
			// Ensure wallet operations are halted and notify relevant parties
		default:
			// General fallback for unspecified errors
		}
	default:
		LogError(fmt.Errorf("unknown error: %v", err))
	}
}

// RecoveryWrapper wraps a function with error recovery
func RecoveryWrapper(f func()) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic recovered: %v", r)
			LogError(err)
		}
	}()
	f()
}
package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/synnergy_network/blockchain/logger"  // Logging package for blockchain-specific logging
)

// CustomError wraps the standard error and adds additional context
type CustomError struct {
	Time    time.Time
	Message string
	Err     error
}

// Error implements the error interface for CustomError
func (ce *CustomError) Error() string {
	return fmt.Sprintf("%s - %v: %s", ce.Time.Format(time.RFC3339), ce.Err, ce.Message)
}

// NewError creates a new CustomError
func NewError(msg string, err error) error {
	return &CustomError{
		Time:    time.Now(),
		Message: msg,
		Err:     err,
	}
}

// HandleError checks the type of error and handles it accordingly
func HandleError(err error) {
	if err != nil {
		switch err := err.(type) {
		case *CustomError:
			// Handle known CustomError differently
			logger.Log("ERROR", err.Error())
		default:
			// Fallback error handling
			logger.Log("ERROR", fmt.Sprintf("An unexpected error occurred: %v", err))
		}

		// Consider whether to halt the system based on the severity
		if criticalErrorOccurred(err) {
			logger.Log("CRITICAL", "A critical error occurred, shutting down the system.")
			os.Exit(1)
		}
	}
}

// criticalErrorOccurred determines if the error is critical
func criticalErrorOccurred(err error) bool {
	// Implement specific checks to determine if the error should be considered critical
	// Placeholder: assume all errors are non-critical
	return false
}

// LogErrorWithTrace logs errors with a stack trace for debugging
func LogErrorWithTrace(msg string, err error) {
	stackTrace := generateStackTrace()
	logger.Log("DEBUG", fmt.Sprintf("%s - %v - Trace: %s", msg, err, stackTrace))
}

// generateStackTrace simulates a stack trace generation
func generateStackTrace() string {
	// Placeholder function to simulate a stack trace
	return "Main -> HandleError -> LogErrorWithTrace"
}
package utils

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain/logger"
	"github.com/synnergy_network/blockchain/security"
)

// Log levels
const (
	DEBUG   = "DEBUG"
	INFO    = "INFO"
	WARNING = "WARNING"
	ERROR   = "ERROR"
	FATAL   = "FATAL"
)

// Logger holds the configuration for the log system
type Logger struct {
	file      *os.File
	mu        sync.Mutex
	logLevels map[string]bool
}

// LogEntry defines the structure of a log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// NewLogger initializes a new Logger instance
func NewLogger(filePath string, levels []string) *Logger {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("error opening log file: %v", err)
	}

	levelMap := make(map[string]bool)
	for _, level := range levels {
		levelMap[level] = true
	}

	return &Logger{
		file:      f,
		logLevels: levelMap,
	}
}

// log writes a message to the log file if the level is enabled
func (l *Logger) log(level, msg string) {
	if l.logLevels[level] {
		l.mu.Lock()
		defer l.mu.Unlock()

		entry := LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Level:     level,
			Message:   msg,
		}
		encodedEntry, err := json.Marshal(entry)
		if err != nil {
			log.Printf("error encoding log entry: %v", err)
			return
		}

		// Encrypt log entry before writing
		encryptedEntry, err := security.EncryptLogEntry(encodedEntry)
		if err != nil {
			log.Printf("error encrypting log entry: %v", err)
			return
		}

		_, err = l.file.Write(encryptedEntry)
		if err != nil {
			log.Printf("error writing to log file: %v", err)
		}
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.log(DEBUG, msg)
}

// Info logs an informational message
func (l *Logger) Info(msg string) {
	l.log(INFO, msg)
}

// Warning logs a warning message
func (l *Logger) Warning(msg string) {
	l.log(WARNING, msg)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.log(ERROR, msg)
}

// Fatal logs a fatal error message and exits the application
func (l *Logger) Fatal(msg string) {
	l.log(FATAL, msg)
	os.Exit(1)
}

// Close cleans up any resources used by the Logger
func (l *Logger) Close() {
	l.file.Close()
}
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
	DefaultTransactionFee   = 0.000000000000000001 // Synthron coin

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
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

const (
	ScryptN       = 32768
	ScryptR       = 8
	ScryptP       = 1
	Argon2Time    = 1
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
)

// GenerateKeyPair generates an ECDSA keypair
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// EncryptAES encrypts data using AES-GCM
func EncryptAES(data, passphrase []byte) (string, error) {
	key := argon2.IDKey(passphrase, nil, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES-GCM
func DecryptAES(encrypted string, passphrase []byte) ([]byte, error) {
	key := argon2.IDKey(passphrase, nil, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	data, err := hex.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateMnemonic generates a mnemonic phrase
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(MnemonicEntropySize)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

// MnemonicToSeed converts a mnemonic to a seed
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	return bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
}

// GenerateHDKeyFromSeed generates an HD key from a seed
func GenerateHDKeyFromSeed(seed []byte) (*hdkeychain.ExtendedKey, error) {
	return hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
}

// CalculateBalance calculates the balance of a wallet from its transactions
func CalculateBalance(address string, transactions []Transaction) (float64, error) {
	var balance float64
	for _, tx := range transactions {
		if tx.ToAddress == address {
			balance += tx.Amount
		}
		if tx.FromAddress == address {
			balance -= tx.Amount
		}
	}
	return balance, nil
}

// HashSHA256 hashes data using SHA-256
func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// GenerateAddressFromPublicKey generates a wallet address from a public key
func GenerateAddressFromPublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash := HashSHA256(pubKeyBytes)
	return hex.EncodeToString(hash), nil
}

// EncryptMnemonic encrypts a mnemonic phrase using AES
func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	return EncryptAES([]byte(mnemonic), []byte(passphrase))
}

// DecryptMnemonic decrypts an encrypted mnemonic phrase using AES
func DecryptMnemonic(encrypted, passphrase string) (string, error) {
	decrypted, err := DecryptAES(encrypted, []byte(passphrase))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// ValidateAddress validates a wallet address
func ValidateAddress(address string) bool {
	_, err := hex.DecodeString(address)
	return err == nil
}

// VerifySignature verifies the signature of a message
func VerifySignature(pubKey *ecdsa.PublicKey, message, signature []byte) bool {
	r := big.Int{}
	s := big.Int{}
	sigLen := len(signature)
	r.SetBytes(signature[:(sigLen / 2)])
	s.SetBytes(signature[(sigLen / 2):])

	hash := HashSHA256(message)
	return ecdsa.Verify(pubKey, hash, &r, &s)
}
