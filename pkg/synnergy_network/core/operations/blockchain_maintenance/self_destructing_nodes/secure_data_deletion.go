package self_destructing_nodes

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "os"

    "github.com/synnergy_network/utils"
)

// SecureDataDeletion provides secure deletion of sensitive data from the blockchain nodes
type SecureDataDeletion struct {
    EncryptionKey []byte
}

// NewSecureDataDeletion creates a new instance of SecureDataDeletion
func NewSecureDataDeletion(key string) *SecureDataDeletion {
    hash := sha256.Sum256([]byte(key))
    return &SecureDataDeletion{
        EncryptionKey: hash[:],
    }
}

// EncryptData encrypts the given data using AES encryption
func (s *SecureDataDeletion) EncryptData(data []byte) (string, error) {
    block, err := aes.NewCipher(s.EncryptionKey)
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
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given encrypted data using AES encryption
func (s *SecureDataDeletion) DecryptData(encData string) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(encData)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(s.EncryptionKey)
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

// SecureDelete securely deletes a file by overwriting it with random data
func (s *SecureDataDeletion) SecureDelete(filePath string) error {
    file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
    if err != nil {
        return err
    }
    defer file.Close()

    info, err := file.Stat()
    if err != nil {
        return err
    }

    randomData := make([]byte, info.Size())
    if _, err = rand.Read(randomData); err != nil {
        return err
    }

    if _, err = file.Write(randomData); err != nil {
        return err
    }

    return os.Remove(filePath)
}

// ZeroOut zeroes out the data in the given slice
func (s *SecureDataDeletion) ZeroOut(data []byte) {
    for i := range data {
        data[i] = 0
    }
}

// SelfDestruct initiates the self-destruction protocol by securely deleting sensitive data and shutting down the node
func (s *SecureDataDeletion) SelfDestruct(filePaths []string) error {
    for _, filePath := range filePaths {
        if err := s.SecureDelete(filePath); err != nil {
            return err
        }
    }
    // Additional logic for node shutdown
    // This could involve stopping services, disconnecting from the network, etc.
    return utils.ShutdownNode()
}

// ShutdownNode is a utility function to safely shutdown the node
func ShutdownNode() error {
    // Placeholder for shutdown logic
    // Implement the actual shutdown process here
    return nil
}
