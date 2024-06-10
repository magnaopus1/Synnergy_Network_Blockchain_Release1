package data_protection

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "io"
)

// EncryptionService provides various cryptographic functions.
type EncryptionService struct {
    rsaPrivateKey *rsa.PrivateKey
    rsaPublicKey  *rsa.PublicKey
}

// NewEncryptionService initializes a new EncryptionService with RSA keys.
func NewEncryptionService() (*EncryptionService, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    return &EncryptionService{
        rsaPrivateKey: privateKey,
        rsaPublicKey:  &privateKey.PublicKey,
    }, nil
}

// EncryptDataAES encrypts data using AES-GCM.
func (es *EncryptionService) EncryptDataAES(plainText []byte) ([]byte, error) {
    key := make([]byte, 32) // AES-256
    _, err := rand.Read(key)
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
    nonce := make([]byte, gcm.NonceSize())
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return nil, err
    }
    cipherText := gcm.Seal(nonce, nonce, plainText, nil)
    return cipherText, nil
}

// DecryptDataAES decrypts data using AES-GCM.
func (es *EncryptionService) DecryptDataAES(cipherText []byte) ([]byte, error) {
    key := make([]byte, 32) // AES-256
    _, err := rand.Read(key)
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
    if len(cipherText) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
    return gcm.Open(nil, nonce, cipherText, nil)
}

// ConfigureTLS establishes a TLS configuration for secure communications.
func ConfigureTLS(certFile, keyFile string) (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
    return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// GenerateRSAKeys generates RSA public and private keys for secure key exchange.
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }
    return privateKey, &privateKey.PublicKey, nil
}
