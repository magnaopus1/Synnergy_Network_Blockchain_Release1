package utils

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// Configuration structure to hold all the settings
type Configuration struct {
	mu sync.Mutex

	// General settings
	NodeName            string        `json:"node_name"`
	NetworkID           string        `json:"network_id"`
	ListenAddress       string        `json:"listen_address"`
	BootstrapNodes      []string      `json:"bootstrap_nodes"`
	StoragePath         string        `json:"storage_path"`
	LogLevel            string        `json:"log_level"`
	TransactionTimeout  time.Duration `json:"transaction_timeout"`
	BlockGenerationTime time.Duration `json:"block_generation_time"`

	// Quantum-resistant cryptography settings
	QR_LatticeConfig     LatticeConfig     `json:"qr_lattice_config"`
	QR_HashBasedConfig   HashBasedConfig   `json:"qr_hash_based_config"`
	QR_MultivariateConfig MultivariateConfig `json:"qr_multivariate_config"`

	// Quantum key distribution settings
	QKD_Enabled     bool   `json:"qkd_enabled"`
	QKD_Endpoint    string `json:"qkd_endpoint"`
	QKD_PublicKey   string `json:"qkd_public_key"`
	QKD_PrivateKey  string `json:"qkd_private_key"`

	// Other configurations
	EnableCompression    bool `json:"enable_compression"`
	EnableSelectivePruning bool `json:"enable_selective_pruning"`
}

// LatticeConfig holds configuration for lattice-based cryptography
type LatticeConfig struct {
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	Parameters   string `json:"parameters"`
}

// HashBasedConfig holds configuration for hash-based cryptography
type HashBasedConfig struct {
	Algorithm  string `json:"algorithm"`
	KeySize    int    `json:"key_size"`
	TreeHeight int    `json:"tree_height"`
}

// MultivariateConfig holds configuration for multivariate cryptography
type MultivariateConfig struct {
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	Parameters   string `json:"parameters"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filePath string) (*Configuration, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Configuration{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// SaveConfig saves configuration to a JSON file
func (c *Configuration) SaveConfig(filePath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}

// EncryptData encrypts the data using AES-GCM
func EncryptData(key, plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the data using AES-GCM
func DecryptData(key, ciphertext string) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GenerateArgon2Hash generates a hash using Argon2
func GenerateArgon2Hash(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// GenerateRandomSalt generates a random salt
func GenerateRandomSalt(size int) (string, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}
