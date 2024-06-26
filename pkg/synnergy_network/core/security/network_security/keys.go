package security

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "log"
)

const (
    SaltSize    = 16
    KeyLength   = 32
    ScryptN     = 16384
    ScryptR     = 8
    ScryptP     = 1
    ArgonTime   = 1
    ArgonMemory = 64 * 1024
    ArgonThreads = 4
)

// KeyPair represents a public and private key pair
type KeyPair struct {
    PublicKey  string
    PrivateKey string
}

// GenerateSalt creates a new random salt
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, SaltSize)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}

// GenerateKeyPair generates a new public/private key pair
func GenerateKeyPair() (*KeyPair, error) {
    salt, err := GenerateSalt()
    if err != nil {
        return nil, err
    }

    privateKey, err := generatePrivateKey(salt)
    if err != nil {
        return nil, err
    }

    publicKey := generatePublicKey(privateKey)
    return &KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// generatePrivateKey uses Argon2 to derive a private key from a salt
func generatePrivateKey(salt []byte) (string, error) {
    key := argon2.IDKey([]byte("user-provided-seed"), salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
    return hex.EncodeToString(key), nil
}

// generatePublicKey hashes the private key to create a public key
func generatePublicKey(privateKey string) string {
    hasher := sha256.New()
    hasher.Write([]byte(privateKey))
    return hex.EncodeToString(hasher.Sum(nil))
}

// EncryptPrivateKey encrypts a private key using Scrypt
func EncryptPrivateKey(privateKey string, passphrase string) (string, error) {
    salt, err := GenerateSalt()
    if err != nil {
        return "", err
    }
    dk, err := scrypt.Key([]byte(privateKey), salt, ScryptN, ScryptR, ScryptP, KeyLength)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(dk), nil
}

// main function to demonstrate key generation and encryption
func main() {
    keyPair, err := GenerateKeyPair()
    if err != nil {
        log.Fatalf("Failed to generate key pair: %s", err)
    }

    log.Printf("Generated Keys: Public: %s, Private: %s", keyPair.PublicKey, keyPair.PrivateKey)

    encryptedPrivateKey, err := EncryptPrivateKey(keyPair.PrivateKey, "your-strong-passphrase")
    if err != nil {
        log.Fatalf("Failed to encrypt private key: %s", err)
    }

    log.Printf("Encrypted Private Key: %s", encryptedPrivateKey)
}
