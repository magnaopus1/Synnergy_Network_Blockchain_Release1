package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
)

// SecureStorage interface
type SecureStorage interface {
	EncryptAndStore(key, data string) error
	RetrieveAndDecrypt(key string) (string, error)
	DeleteData(key string) error
}

// AES based implementation of SecureStorage
type SecureStorageAES struct {
	storage storage.Storage
	salt    []byte
}

// NewSecureStorageAES creates a new instance of SecureStorageAES
func NewSecureStorageAES(storage storage.Storage, salt []byte) *SecureStorageAES {
	return &SecureStorageAES{
		storage: storage,
		salt:    salt,
	}
}

// EncryptAndStore encrypts the data and stores it in the storage
func (s *SecureStorageAES) EncryptAndStore(key, data string) error {
	encryptedData, err := s.encrypt(data)
	if err != nil {
		return err
	}

	return s.storage.Put(key, encryptedData)
}

// RetrieveAndDecrypt retrieves the encrypted data from storage and decrypts it
func (s *SecureStorageAES) RetrieveAndDecrypt(key string) (string, error) {
	encryptedData, err := s.storage.Get(key)
	if err != nil {
		return "", err
	}

	decryptedData, err := s.decrypt(encryptedData.(string))
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}

// DeleteData deletes the data associated with the key from storage
func (s *SecureStorageAES) DeleteData(key string) error {
	return s.storage.Delete(key)
}

// Encrypt encrypts the plain text using AES
func (s *SecureStorageAES) encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(s.deriveKey())
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

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts the cipher text using AES
func (s *SecureStorageAES) decrypt(cipherText string) (string, error) {
	block, err := aes.NewCipher(s.deriveKey())
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// deriveKey derives a key from the salt using scrypt
func (s *SecureStorageAES) deriveKey() []byte {
	key, _ := scrypt.Key([]byte("password"), s.salt, 32768, 8, 1, 32)
	return key
}

// HashPassword hashes a password using SHA-256
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// VerifyPassword verifies a password against its hash
func VerifyPassword(password, hash string) bool {
	return HashPassword(password) == hash
}
