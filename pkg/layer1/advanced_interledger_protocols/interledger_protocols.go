package interledger

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "io"

    "golang.org/x/crypto/argon2"
)

// InterledgerProtocol defines the structure and methods for interledger operations
type InterledgerProtocol struct {
    ProtocolID string
}

// NewInterledgerProtocol creates a new instance of interledger protocol handler
func NewInterledgerProtocol(protocolID string) *InterledgerProtocol {
    return &InterledgerProtocol{
        ProtocolID: protocolID,
    }
}

// EncryptData handles the encryption of data intended for cross-chain transfers
func (ip *InterledgerProtocol) EncryptData(data []byte, passphrase string) (string, error) {
    salt := generateSalt()
    if salt == nil {
        return "", errors.New("failed to generate salt for encryption")
    }

    key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    encrypted := gcm.Seal(nonce, nonce, data, nil)
    return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts data received from a cross-chain transfer
func (ip *InterledgerProtocol) DecryptData(encryptedData, passphrase string) ([]byte, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    salt := extractSalt(data) // You need to implement this method to extract the salt from data
    key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// generateSalt generates a secure random salt
func generateSalt() []byte {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil
    }
    return salt
}

// extractSalt is a placeholder for the method to extract salt from encrypted data
func extractSalt(data []byte) []byte {
    // Implement the logic to extract salt based on how it's embedded in the encrypted data
    return data[:16] // Example assuming salt is the first 16 bytes
}
