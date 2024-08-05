package operator

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "log"

    "golang.org/x/crypto/scrypt"
)

// SecurityConfig holds the configuration for security measures
type SecurityConfig struct {
    ScryptN   int
    ScryptR   int
    ScryptP   int
    KeyLength int
}

// SecurityMeasures represents the security system for the operator
type SecurityMeasures struct {
    config SecurityConfig
}

// NewSecurityMeasures initializes a new SecurityMeasures
func NewSecurityMeasures(config SecurityConfig) *SecurityMeasures {
    return &SecurityMeasures{
        config: config,
    }
}

// EncryptData encrypts data using AES with a key derived from scrypt
func (sm *SecurityMeasures) EncryptData(data, passphrase string) (string, error) {
    key, salt, err := sm.generateKey(passphrase)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
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

    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// DecryptData decrypts data using AES with a key derived from scrypt
func (sm *SecurityMeasures) DecryptData(data, passphrase string) (string, error) {
    decodedData, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return "", err
    }

    salt := decodedData[:sm.config.KeyLength]
    ciphertext := decodedData[sm.config.KeyLength:]

    key, err := sm.deriveKey(passphrase, salt)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// generateKey generates a key from the passphrase using scrypt
func (sm *SecurityMeasures) generateKey(passphrase string) ([]byte, []byte, error) {
    salt := make([]byte, sm.config.KeyLength)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, err
    }

    key, err := sm.deriveKey(passphrase, salt)
    if err != nil {
        return nil, nil, err
    }

    return key, salt, nil
}

// deriveKey derives a key from the passphrase and salt using scrypt
func (sm *SecurityMeasures) deriveKey(passphrase string, salt []byte) ([]byte, error) {
    key, err := scrypt.Key([]byte(passphrase), salt, sm.config.ScryptN, sm.config.ScryptR, sm.config.ScryptP, sm.config.KeyLength)
    if err != nil {
        return nil, err
    }

    return key, nil
}

// hashData hashes data using SHA-256
func (sm *SecurityMeasures) hashData(data string) string {
    hash := sha256.Sum256([]byte(data))
    return base64.StdEncoding.EncodeToString(hash[:])
}

// VerifyData verifies if the hash matches the data
func (sm *SecurityMeasures) VerifyData(data, hash string) bool {
    return sm.hashData(data) == hash
}

// LogSecurityIncident logs a security incident
func (sm *SecurityMeasures) LogSecurityIncident(incident string) {
    log.Printf("Security Incident: %s", incident)
}

// PerformSecurityAudit performs a security audit and logs any issues found
func (sm *SecurityMeasures) PerformSecurityAudit() {
    // Placeholder for a real audit implementation
    log.Println("Performing security audit...")

    // Check for known issues
    // Example: Check if any configuration is not secure
    if sm.config.ScryptN < 16384 || sm.config.ScryptR < 8 || sm.config.ScryptP < 1 {
        sm.LogSecurityIncident("Scrypt parameters are too weak.")
    }

    // Example: Check if key length is adequate
    if sm.config.KeyLength < 32 {
        sm.LogSecurityIncident("Key length is too short.")
    }

    log.Println("Security audit completed.")
}
