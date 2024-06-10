package data_security

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "errors"
)

// EncryptionProtocols provides a structured way to handle AES encryption and decryption
// specifically tuned for IoT devices within blockchain interaction contexts.
type EncryptionProtocols struct {
    key []byte
}

// NewEncryptionProtocols initializes and returns a new EncryptionProtocols with a given key.
func NewEncryptionProtocols(key []byte) (*EncryptionProtocols, error) {
    if len(key) != 32 { // AES-256 requires a 32-byte key
        return nil, errors.New("invalid key size: must be 32 bytes")
    }
    return &EncryptionProtocols{key: key}, nil
}

// Encrypt encrypts data using AES-256-GCM.
func (e *EncryptionProtocols) Encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    encrypted := gcm.Seal(nonce, nonce, data, nil)
    return encrypted, nil
}

// Decrypt decrypts data using AES-256-GCM.
func (e *EncryptionProtocols) Decrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(data) < gcm.NonceSize() {
        return nil, errors.New("malformed ciphertext")
    }

    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return decrypted, nil
}

// Example usage and setup for module testing
func ExampleUsage() error {
    key := make([]byte, 32) // Generate a random 256-bit key for AES-256
    _, err := rand.Read(key)
    if err != nil {
        return err
    }

    ep, err := NewEncryptionProtocols(key)
    if err != nil {
        return err
    }

    originalText := []byte("Hello IoT Blockchain!")
    encryptedText, err := ep.Encrypt(originalText)
    if err != nil {
        return err
    }

    decryptedText, err := ep.Decrypt(encryptedText)
    if err != nil {
        return err
    }

    if string(decryptedText) != string(originalText) {
        return errors.New("decryption failed")
    }
    return nil
}
