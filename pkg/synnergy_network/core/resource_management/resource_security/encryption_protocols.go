package resource_security

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "golang.org/x/crypto/argon2"
    "io"
    "io/ioutil"
    "os"
)

// AES encryption with secure key management
type AESCipher struct {
    key []byte
}

func NewAESCipher(key []byte) (*AESCipher, error) {
    if len(key) != 32 {
        return nil, errors.New("key must be 32 bytes long")
    }
    return &AESCipher{key: key}, nil
}

func (a *AESCipher) Encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(a.key)
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
    return gcm.Seal(nonce, nonce, data, nil), nil
}

func (a *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(a.key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// Argon2 password hashing
func HashPassword(password string, salt []byte) []byte {
    return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// RSA Encryption
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, bits)
}

func ExportRSAKey(key *rsa.PrivateKey) ([]byte, error) {
    keyBytes := x509.MarshalPKCS1PrivateKey(key)
    return pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: keyBytes,
    }), nil
}

func ParseRSAKey(pemData []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(pemData)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("invalid PEM data")
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func EncryptRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
    return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

func DecryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
}

// Data Integrity
func HashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

// Save and load key management
func SaveKey(key []byte, filepath string) error {
    return ioutil.WriteFile(filepath, key, 0644)
}

func LoadKey(filepath string) ([]byte, error) {
    return ioutil.ReadFile(filepath)
}

// Implement secure channels, access controls, and digital signatures as needed
