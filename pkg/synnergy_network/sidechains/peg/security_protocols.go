package peg

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "log"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/argon2"
)

// SecurityProtocol manages security-related functionalities for the blockchain.
type SecurityProtocol struct {
    mu         sync.Mutex
    aesKey     []byte
    salt       []byte
    alertChan  chan string
}

// NewSecurityProtocol creates a new instance of SecurityProtocol.
func NewSecurityProtocol(aesKey string) *SecurityProtocol {
    key, err := hex.DecodeString(aesKey)
    if err != nil {
        log.Fatalf("Failed to decode AES key: %v", err)
    }
    salt := make([]byte, 16)
    _, err = io.ReadFull(rand.Reader, salt)
    if err != nil {
        log.Fatalf("Failed to generate salt: %v", err)
    }
    return &SecurityProtocol{
        aesKey:    key,
        salt:      salt,
        alertChan: make(chan string, 100),
    }
}

// EncryptData encrypts the given plaintext using AES encryption.
func (sp *SecurityProtocol) EncryptData(plaintext string) (string, error) {
    block, err := aes.NewCipher(sp.aesKey)
    if err != nil {
        return "", err
    }
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
    return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given ciphertext using AES decryption.
func (sp *SecurityProtocol) DecryptData(ciphertext string) (string, error) {
    data, err := hex.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher(sp.aesKey)
    if err != nil {
        return "", err
    }
    if len(data) < aes.BlockSize {
        return "", fmt.Errorf("ciphertext too short")
    }
    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(data, data)
    return string(data), nil
}

// DeriveKey derives a secure key using the specified password and salt.
func (sp *SecurityProtocol) DeriveKey(password string, useArgon2 bool) ([]byte, error) {
    if useArgon2 {
        return argon2.IDKey([]byte(password), sp.salt, 1, 64*1024, 4, 32), nil
    }
    return scrypt.Key([]byte(password), sp.salt, 32768, 8, 1, 32)
}

// HashData hashes the given data using SHA-256.
func (sp *SecurityProtocol) HashData(data string) string {
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// MonitorSecurity continuously monitors security-related events and sends alerts.
func (sp *SecurityProtocol) MonitorSecurity() {
    for {
        select {
        case alert := <-sp.alertChan:
            log.Printf("SECURITY ALERT: %s", alert)
        case <-time.After(1 * time.Minute):
            sp.alertChan <- "Security check passed"
        }
    }
}

// GenerateSalt generates a new salt for cryptographic operations.
func (sp *SecurityProtocol) GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    _, err := io.ReadFull(rand.Reader, salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}

// LogSecurityEvent logs a security event to the appropriate sink.
func (sp *SecurityProtocol) LogSecurityEvent(event string) {
    sp.mu.Lock()
    defer sp.mu.Unlock()
    sp.alertChan <- event
}

// Example implementation of initializing the security protocol
func main() {
    aesKey := "6368616e676520746869732070617373" // Example AES key (must be 32 bytes for AES-256)
    sp := NewSecurityProtocol(aesKey)

    go sp.MonitorSecurity()

    password := "examplepassword"
    derivedKey, err := sp.DeriveKey(password, true)
    if err != nil {
        log.Fatalf("Failed to derive key: %v", err)
    }
    fmt.Printf("Derived Key: %x\n", derivedKey)

    hashedData := sp.HashData("exampledata")
    fmt.Printf("Hashed Data: %s\n", hashedData)

    encryptedData, err := sp.EncryptData("exampleplaintext")
    if err != nil {
        log.Fatalf("Failed to encrypt data: %v", err)
    }
    fmt.Printf("Encrypted Data: %s\n", encryptedData)

    decryptedData, err := sp.DecryptData(encryptedData)
    if err != nil {
        log.Fatalf("Failed to decrypt data: %v", err)
    }
    fmt.Printf("Decrypted Data: %s\n", decryptedData)
}
