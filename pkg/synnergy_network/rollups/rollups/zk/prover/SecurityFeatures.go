package prover

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// SecurityFeatures provides methods to enhance the security of the proving network.
type SecurityFeatures struct {
	EncryptionKey []byte
	Salt          []byte
}

// NewSecurityFeatures initializes a new SecurityFeatures instance with a given encryption key.
func NewSecurityFeatures(key string) *SecurityFeatures {
	salt := generateRandomBytes(16)
	return &SecurityFeatures{
		EncryptionKey: argon2.IDKey([]byte(key), salt, 1, 64*1024, 4, 32),
		Salt:          salt,
	}
}

// Encrypt encrypts the given plaintext using AES encryption.
func (sf *SecurityFeatures) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(sf.EncryptionKey)
	if err != nil {
		return "", err
	}

	nonce := generateRandomBytes(12)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES decryption.
func (sf *SecurityFeatures) Decrypt(ciphertext string) (string, error) {
	block, err := aes.NewCipher(sf.EncryptionKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashData generates a SHA-256 hash of the given data.
func (sf *SecurityFeatures) HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// VerifyHash verifies if the given hash matches the data.
func (sf *SecurityFeatures) VerifyHash(data, hash string) bool {
	expectedHash := sf.HashData(data)
	return expectedHash == hash
}

// GenerateProof generates a proof using the given data and difficulty.
func (sf *SecurityFeatures) GenerateProof(data string, difficulty int) (string, error) {
	nonce := 0
	for {
		combinedData := fmt.Sprintf("%s:%d", data, nonce)
		hash := sf.HashData(combinedData)
		if isValidProof(hash, difficulty) {
			return fmt.Sprintf("%s:%d", hash, nonce), nil
		}
		nonce++
	}
}

// ValidateProof validates the proof with the given data and difficulty.
func (sf *SecurityFeatures) ValidateProof(data, proof string, difficulty int) bool {
	proofParts := strings.Split(proof, ":")
	if len(proofParts) != 2 {
		return false
	}
	hash, nonceStr := proofParts[0], proofParts[1]
	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		return false
	}

	combinedData := fmt.Sprintf("%s:%d", data, nonce)
	expectedHash := sf.HashData(combinedData)
	return isValidProof(expectedHash, difficulty) && expectedHash == hash
}

// isValidProof checks if the hash meets the required difficulty.
func isValidProof(hash string, difficulty int) bool {
	prefix := ""
	for i := 0; i < difficulty; i++ {
		prefix += "0"
	}
	return hash[:difficulty] == prefix
}

// generateRandomBytes generates a slice of random bytes of the given size.
func generateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return bytes
}
