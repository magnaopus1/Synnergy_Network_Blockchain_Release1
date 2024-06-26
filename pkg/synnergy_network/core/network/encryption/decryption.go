package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "io"

    "golang.org/x/crypto/ssh"
)

// DecryptionManager handles the decryption processes using various cryptographic algorithms.
type DecryptionManager struct {
    privateKey *rsa.PrivateKey
}

// NewDecryptionManager initializes a new decryption manager with a RSA private key.
func NewDecryptionManager(pemBytes []byte) (*DecryptionManager, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the key")
    }

    privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return &DecryptionManager{privateKey: privKey}, nil
}

// DecryptAES decrypts data using AES-GCM.
func (dm *DecryptionManager) DecryptAES(ciphertext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecryptRSA decrypts data using RSA-OAEP.
func (dm *DecryptionManager) DecryptRSA(ciphertext []byte) ([]byte, error) {
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, dm.privateKey, ciphertext, nil)
}

// Example usage and integration
func main() {
    // Initialize decryption manager with RSA private key
    decryptionManager, err := NewDecryptionManager([]byte("your-rsa-private-key-pem"))
    if err != nil {
        panic(err)
    }

    // Example AES decryption
    encryptedData := []byte("your-encrypted-data")
    aesKey := []byte("your-aes-key")
    decryptedData, err := decryptionManager.DecryptAES(encryptedData, aesKey)
    if err != nil {
        panic(err)
    }

    // Example RSA decryption
    rsaEncryptedData := []byte("your-rsa-encrypted-data")
    rsaDecryptedData, err := decryptionManager.DecryptRSA(rsaEncryptedData)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted AES data: %s\n", decryptedData)
    fmt.Printf("Decrypted RSA data: %s\n", rsaDecrypted one)
}
