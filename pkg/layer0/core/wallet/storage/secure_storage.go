package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// SecureStorageService provides methods for securely storing and retrieving sensitive data.
type SecureStorageService struct {
	storage sync.Map // map[string]string for encrypted data storage
}

// NewSecureStorageService initializes and returns a new SecureStorageService.
func NewSecureStorageService() *SecureStorageService {
	return &SecureStorageService{}
}

// Store securely stores data with a given key and passphrase.
func (sss *SecureStorageService) Store(key, data, passphrase string) error {
	encryptedData, err := sss.encrypt([]byte(data), passphrase)
	if err != nil {
		return err
	}
	sss.storage.Store(key, encryptedData)
	return nil
}

// Retrieve retrieves and decrypts data for a given key and passphrase.
func (sss *SecureStorageService) Retrieve(key, passphrase string) (string, error) {
	encryptedData, ok := sss.storage.Load(key)
	if !ok {
		return "", errors.New("data not found")
	}
	decryptedData, err := sss.decrypt(encryptedData.(string), passphrase)
	if err != nil {
		return "", err
	}
	return string(decryptedData), nil
}

// encrypt encrypts data using AES with a provided passphrase.
func (sss *SecureStorageService) encrypt(data []byte, passphrase string) (string, error) {
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES with a provided passphrase.
func (sss *SecureStorageService) decrypt(encrypted string, passphrase string) ([]byte, error) {
	key := sha256.Sum256([]byte(passphrase))
	ciphertext, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// GenerateArgon2Key generates a key using Argon2 key derivation function.
func (sss *SecureStorageService) GenerateArgon2Key(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// GenerateScryptKey generates a key using Scrypt key derivation function.
func (sss *SecureStorageService) GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 1<<15, 8, 1, 32)
}

// SecureDataWithArgon2 securely stores data using Argon2 for key derivation.
func (sss *SecureStorageService) SecureDataWithArgon2(key, data, password string, salt []byte) error {
	derivedKey, err := sss.GenerateArgon2Key([]byte(password), salt)
	if err != nil {
		return err
	}
	return sss.Store(key, data, string(derivedKey))
}

// SecureDataWithScrypt securely stores data using Scrypt for key derivation.
func (sss *SecureStorageService) SecureDataWithScrypt(key, data, password string, salt []byte) error {
	derivedKey, err := sss.GenerateScryptKey([]byte(password), salt)
	if err != nil {
		return err
	}
	return sss.Store(key, data, string(derivedKey))
}

// RetrieveDataWithArgon2 retrieves and decrypts data using Argon2 for key derivation.
func (sss *SecureStorageService) RetrieveDataWithArgon2(key, password string, salt []byte) (string, error) {
	derivedKey, err := sss.GenerateArgon2Key([]byte(password), salt)
	if err != nil {
		return "", err
	}
	return sss.Retrieve(key, string(derivedKey))
}

// RetrieveDataWithScrypt retrieves and decrypts data using Scrypt for key derivation.
func (sss *SecureStorageService) RetrieveDataWithScrypt(key, password string, salt []byte) (string, error) {
	derivedKey, err := sss.GenerateScryptKey([]byte(password), salt)
	if err != nil {
		return "", err
	}
	return sss.Retrieve(key, string(derivedKey))
}

func main() {
	// Example usage
	sss := NewSecureStorageService()

	// Store data with AES encryption
	passphrase := "strongpassphrase"
	key := "exampleKey"
	data := "sensitive data"
	err := sss.Store(key, data, passphrase)
	if err != nil {
		panic(err)
	}

	// Retrieve data
	retrievedData, err := sss.Retrieve(key, passphrase)
	if err != nil {
		panic(err)
	}
	println("Retrieved data:", retrievedData)

	// Using Argon2 for key derivation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	password := "password123"
	err = sss.SecureDataWithArgon2(key, data, password, salt)
	if err != nil {
		panic(err)
	}

	retrievedData, err = sss.RetrieveDataWithArgon2(key, password, salt)
	if err != nil {
		panic(err)
	}
	println("Retrieved data with Argon2:", retrievedData)

	// Using Scrypt for key derivation
	err = sss.SecureDataWithScrypt(key, data, password, salt)
	if err != nil {
		panic(err)
	}

	retrievedData, err = sss.RetrieveDataWithScrypt(key, password, salt)
	if err != nil {
		panic(err)
	}
	println("Retrieved data with Scrypt:", retrievedData)
}
