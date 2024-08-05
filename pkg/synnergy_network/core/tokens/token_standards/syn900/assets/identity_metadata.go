package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"time"
)

// IdentityMetadata represents detailed personal information for an identity token
type IdentityMetadata struct {
	FullName         string `json:"full_name"`
	DateOfBirth      string `json:"date_of_birth"`
	Nationality      string `json:"nationality"`
	PhotographHash   string `json:"photograph_hash"`
	PhysicalAddress  string `json:"physical_address"`
	DrivingLicense   string `json:"driving_license"`
	EncryptedPassNum string `json:"encrypted_pass_num"`
}

// EncryptData encrypts data using AES encryption with Argon2 key derivation
func EncryptData(plainText, password string) (string, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptData decrypts AES encrypted data with Argon2 key derivation
func DecryptData(cipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
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

// HashData hashes data using SHA-256
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ValidateMetadata ensures all required fields are present and correctly formatted
func (im *IdentityMetadata) ValidateMetadata() error {
	if im.FullName == "" {
		return errors.New("full name is required")
	}
	if im.DateOfBirth == "" {
		return errors.New("date of birth is required")
	}
	if im.Nationality == "" {
		return errors.New("nationality is required")
	}
	if im.PhotographHash == "" {
		return errors.New("photograph hash is required")
	}
	if im.PhysicalAddress == "" {
		return errors.New("physical address is required")
	}
	if im.DrivingLicense == "" {
		return errors.New("driving license is required")
	}
	if im.EncryptedPassNum == "" {
		return errors.New("encrypted passport number is required")
	}
	return nil
}

// SaveMetadata serializes the identity metadata to JSON
func (im *IdentityMetadata) SaveMetadata() (string, error) {
	data, err := json.Marshal(im)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadMetadata deserializes the identity metadata from JSON
func LoadMetadata(data string) (*IdentityMetadata, error) {
	var metadata IdentityMetadata
	err := json.Unmarshal([]byte(data), &metadata)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// Example usage of IdentityMetadata
func main() {
	identity := IdentityMetadata{
		FullName:        "John Doe",
		DateOfBirth:     "1990-01-01",
		Nationality:     "US",
		PhotographHash:  "examplehash",
		PhysicalAddress: "1234 Blockchain Ave",
		DrivingLicense:  HashData("D1234567"),
	}

	password := "strongpassword"
	encryptedPassNumber, err := EncryptData("P1234567", password)
	if err != nil {
		fmt.Println("Error encrypting passport number:", err)
		return
	}
	identity.EncryptedPassNum = encryptedPassNumber

	if err := identity.ValidateMetadata(); err != nil {
		fmt.Println("Validation error:", err)
		return
	}

	savedMetadata, err := identity.SaveMetadata()
	if err != nil {
		fmt.Println("Error saving metadata:", err)
		return
	}

	loadedMetadata, err := LoadMetadata(savedMetadata)
	if err != nil {
		fmt.Println("Error loading metadata:", err)
		return
	}

	fmt.Printf("Loaded Metadata: %+v\n", loadedMetadata)
}
