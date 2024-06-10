package governance_framework

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "log"

    "github.com/pkg/errors"
)

// SecurityConfig holds the security configurations for the voting system.
type SecurityConfig struct {
    EncryptionKey []byte // AES key for encrypting votes
    HashSalt      []byte // Salt for hashing identifiers
}

// NewSecurityConfig generates a new security configuration with random keys.
func NewSecurityConfig() (*SecurityConfig, error) {
    encryptionKey := make([]byte, 32) // 256-bit key for AES
    salt := make([]byte, 16)          // 128-bit salt for hashing

    if _, err := rand.Read(encryptionKey); err != nil {
        return nil, errors.Wrap(err, "failed to generate encryption key")
    }
    if _, err := rand.Read(salt); err != nil {
        return nil, errors.Wrap(err, "failed to generate hash salt")
    }

    return &SecurityConfig{
        EncryptionKey: encryptionKey,
        HashSalt:      salt,
    }, nil
}

// EncryptVoteData encrypts vote data using AES-256 GCM.
func EncryptVoteData(data []byte, config *SecurityConfig) ([]byte, error) {
    block, err := aes.NewCipher(config.EncryptionKey)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create cipher block")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create GCM")
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, errors.Wrap(err, "failed to create nonce")
    }

    encryptedData := gcm.Seal(nil, nonce, data, nil)
    return encryptedData, nil
}

// DecryptVoteData decrypts vote data using AES-256 GCM.
func DecryptVoteData(encryptedData []byte, config *SecurityConfig) ([]byte, error) {
    block, err := aes.NewCipher(config.EncryptionKey)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create cipher block")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create GCM")
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return nil, errors.New("encrypted data is too short")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, errors.Wrap(err, "failed to decrypt data")
    }

    return decryptedData, nil
}

// HashIdentifier hashes voter or candidate identifiers using SHA-256 and a salt.
func HashIdentifier(identifier string, config *SecurityConfig) string {
    hasher := sha256.New()
    hasher.Write(config.HashSalt)
    hasher.Write([]byte(identifier))
    return hex.EncodeToString(hasher.Sum(nil))
}

// LogSecurityEvent logs security-related events or errors.
func LogSecurityEvent(event string) {
    log.Println("Security Event:", event)
}
