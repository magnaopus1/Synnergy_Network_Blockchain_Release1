package compression

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io"
	"log"
	"os"
)

// AdaptiveCompression provides adaptive compression and encryption functionalities.
type AdaptiveCompression struct {
	key []byte
}

// NewAdaptiveCompression initializes the AdaptiveCompression with a passphrase.
func NewAdaptiveCompression(passphrase string) (*AdaptiveCompression, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &AdaptiveCompression{
		key: key,
	}, nil
}

// CompressAndEncrypt compresses and encrypts the given data.
func (ac *AdaptiveCompression) CompressAndEncrypt(data []byte) ([]byte, error) {
	// Apply your compression algorithm here
	compressedData := data // Replace this with actual compression logic

	encryptedData, err := encrypt(compressedData, ac.key)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptAndDecompress decrypts and decompresses the given data.
func (ac *AdaptiveCompression) DecryptAndDecompress(encryptedData []byte) ([]byte, error) {
	decryptedData, err := decrypt(encryptedData, ac.key)
	if err != nil {
		return nil, err
	}

	// Apply your decompression algorithm here
	decompressedData := decryptedData // Replace this with actual decompression logic

	return decompressedData, nil
}

// generateKey derives a key from the given passphrase using scrypt.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// encrypt encrypts the given data with the provided key using AES.
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// decrypt decrypts the given data with the provided key using AES.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// SaveToFile saves the encrypted data to a file.
func (ac *AdaptiveCompression) SaveToFile(filename string, data []byte) error {
	encryptedData, err := ac.CompressAndEncrypt(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadFromFile loads and decrypts data from a file.
func (ac *AdaptiveCompression) LoadFromFile(filename string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := ac.DecryptAndDecompress(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GenerateHash generates a SHA-256 hash of the given data.
func GenerateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyIntegrity verifies the integrity of the data by comparing its hash.
func VerifyIntegrity(data []byte, hash string) bool {
	return GenerateHash(data) == hash
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}
