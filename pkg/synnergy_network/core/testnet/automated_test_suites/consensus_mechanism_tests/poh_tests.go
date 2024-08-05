package ai_powered_anomaly_detection

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "golang.org/x/crypto/scrypt"
)

// EncryptData encrypts the given data using AES encryption with a provided passphrase
func EncryptData(data, passphrase string) (string, error) {
    key, salt, err := deriveKey(passphrase)
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
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    encrypted := gcm.Seal(nonce, nonce, []byte(data), nil)
    result := append(salt, encrypted...)
    return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptData decrypts the given data using AES encryption with a provided passphrase
func DecryptData(encryptedData, passphrase string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }

    salt := data[:32]
    key, _, err := deriveKeyWithSalt(passphrase, salt)
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
    nonce, ciphertext := data[32:32+nonceSize], data[32+nonceSize:]

    decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(decrypted), nil
}

// deriveKey derives a key from a passphrase using scrypt and generates a salt
func deriveKey(passphrase string) ([]byte, []byte, error) {
    salt := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, err
    }
    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, nil, err
    }
    return key, salt, nil
}

// deriveKeyWithSalt derives a key from a passphrase using scrypt with a provided salt
func deriveKeyWithSalt(passphrase string, salt []byte) ([]byte, []byte, error) {
    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, nil, err
    }
    return key, salt, nil
}

// HashData hashes the given data using SHA-256
func HashData(data string) string {
    hash := sha256.New()
    hash.Write([]byte(data))
    return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// ValidateHash validates the given data against the given hash
func ValidateHash(data, hash string) bool {
    computedHash := HashData(data)
    return computedHash == hash
}

// DataSecurityLayer ensures data security during collection and analysis
func DataSecurityLayer(data, passphrase string) (string, error) {
    encryptedData, err := EncryptData(data, passphrase)
    if err != nil {
        return "", err
    }

    hash := HashData(data)
    return encryptedData + ":" + hash, nil
}

// VerifyDataSecurityLayer verifies the data integrity and decrypts it
func VerifyDataSecurityLayer(encryptedDataWithHash, passphrase string) (string, error) {
    parts := splitDataHash(encryptedDataWithHash)
    if len(parts) != 2 {
        return "", errors.New("invalid data format")
    }

    decryptedData, err := DecryptData(parts[0], passphrase)
    if err != nil {
        return "", err
    }

    if !ValidateHash(decryptedData, parts[1]) {
        return "", errors.New("data integrity check failed")
    }

    return decryptedData, nil
}

// splitDataHash splits the concatenated encrypted data and hash
func splitDataHash(dataHash string) []string {
    return strings.Split(dataHash, ":")
}
