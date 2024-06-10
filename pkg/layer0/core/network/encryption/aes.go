package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"

    "github.com/pkg/errors"
)

// AESManager handles AES encryption and decryption processes.
type AESManager struct {
    Key []byte // AES requires a 16, 24, or 32 bytes key for AES-128, AES-192, or AES-256.
}

// NewAESManager creates a new instance of AESManager with a specified key size.
func NewAESManager(keySize int) (*AESManager, error) {
    if keySize != 16 && keySize != 24 && keySize != 32 {
        return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
    }

    key := make([]byte, keySize)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, errors.Wrap(err, "failed to generate AES key")
    }

    return &AESManager{Key: key}, nil
}

// Encrypt encrypts plaintext using AES-GCM.
func (am *AESManager) Encrypt(plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(am.Key)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create cipher block")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create GCM")
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, errors.Wrap(err, "failed to generate nonce")
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM.
func (am *AESManager) Decrypt(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(am.Key)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create cipher block")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
    return nil, errors.Wrap(err, "failed to create GCM")
    }

    if len(ciphertext) < gcm.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, errors.Wrap(err, "failed to decrypt")
    }

    return plaintext, nil
}

// Example usage
func main() {
    aesManager, err := NewAESManager(32) // using AES-256
    if err != nil {
        panic(err)
    }

    plaintext := []byte("Hello, Synnergy Network!")
    ciphertext, err := aesManager.Encrypt(plaintext)
    if err != nil {
        panic(err)
    }

    result, err := aesManager.Decrypt(ciphertext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted text: %s\n", string(result))
}
