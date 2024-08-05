package core


import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Attachment represents an email attachment with its metadata.
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        []byte `json:"data"`
	Timestamp   int64  `json:"timestamp"`
}

// EncryptAttachment encrypts the attachment data using AES with the given passphrase.
func EncryptAttachment(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptAttachment decrypts the attachment data using AES with the given passphrase.
func DecryptAttachment(data []byte, passphrase string) ([]byte, error) {
	salt := data[:8]
	data = data[8:]

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SaveAttachment saves the attachment to the specified directory.
func SaveAttachment(attachment Attachment, directory string) error {
	path := filepath.Join(directory, attachment.Filename)
	return ioutil.WriteFile(path, attachment.Data, 0644)
}

// LoadAttachment loads the attachment from the specified file.
func LoadAttachment(filename string) (Attachment, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Attachment{}, err
	}

	info, err := os.Stat(filename)
	if err != nil {
		return Attachment{}, err
	}

	return Attachment{
		Filename:    filepath.Base(filename),
		ContentType: "application/octet-stream",
		Size:        info.Size(),
		Data:        data,
		Timestamp:   time.Now().Unix(),
	}, nil
}

// EncodeToBase64 encodes the attachment data to a base64 string.
func EncodeToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeFromBase64 decodes the base64 string to attachment data.
func DecodeFromBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// GenerateHash generates a SHA256 hash for the given data.
func GenerateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// LogAttachment logs the attachment metadata.
func LogAttachment(attachment Attachment) {
	log.Printf("Attachment: Filename=%s, ContentType=%s, Size=%d, Timestamp=%d",
		attachment.Filename, attachment.ContentType, attachment.Size, attachment.Timestamp)
}

// SaveEncryptedAttachment saves the encrypted attachment to the specified directory.
func SaveEncryptedAttachment(attachment Attachment, directory, passphrase string) error {
	encryptedData, err := EncryptAttachment(attachment.Data, passphrase)
	if err != nil {
		return err
	}

	attachment.Data = encryptedData
	return SaveAttachment(attachment, directory)
}

// LoadEncryptedAttachment loads and decrypts the attachment from the specified file.
func LoadEncryptedAttachment(filename, passphrase string) (Attachment, error) {
	attachment, err := LoadAttachment(filename)
	if err != nil {
		return Attachment{}, err
	}

	decryptedData, err := DecryptAttachment(attachment.Data, passphrase)
	if err != nil {
		return Attachment{}, err
	}

	attachment.Data = decryptedData
	return attachment, nil
}

// SecureDelete securely deletes a file by overwriting it with random data before deletion.
func SecureDelete(filename string) error {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return err
	}

	size := fileInfo.Size()
	randomData := make([]byte, size)
	if _, err := rand.Read(randomData); err != nil {
		return err
	}

	if err := ioutil.WriteFile(filename, randomData, 0644); err != nil {
		return err
	}

	return os.Remove(filename)
}
