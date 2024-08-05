package compression

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// CompressionAlgorithm represents the interface for different compression algorithms.
type CompressionAlgorithm interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

// GzipCompression implements gzip compression.
type GzipCompression struct{}

func (gc *GzipCompression) Compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (gc *GzipCompression) Decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

// ZlibCompression implements zlib compression.
type ZlibCompression struct{}

func (zc *ZlibCompression) Compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (zc *ZlibCompression) Decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

// EncryptionManager handles encryption and decryption using AES and Argon2.
type EncryptionManager struct {
	key []byte
}

// NewEncryptionManager initializes the EncryptionManager with a passphrase.
func NewEncryptionManager(passphrase string) (*EncryptionManager, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}
	return &EncryptionManager{key: key}, nil
}

// Encrypt encrypts the given data using AES.
func (em *EncryptionManager) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(em.key)
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

// Decrypt decrypts the given data using AES.
func (em *EncryptionManager) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(em.key)
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

// generateKey derives a key from the given passphrase using Argon2.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, nil
}

// FileManager handles file operations with encryption and compression.
type FileManager struct {
	compression CompressionAlgorithm
	encryption  *EncryptionManager
}

// NewFileManager initializes the FileManager with the specified compression algorithm and encryption manager.
func NewFileManager(compression CompressionAlgorithm, encryption *EncryptionManager) *FileManager {
	return &FileManager{compression: compression, encryption: encryption}
}

// SaveToFile compresses, encrypts, and saves the data to a file.
func (fm *FileManager) SaveToFile(filename string, data []byte) error {
	compressedData, err := fm.compression.Compress(data)
	if err != nil {
		return err
	}

	encryptedData, err := fm.encryption.Encrypt(compressedData)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, encryptedData, 0644)
}

// LoadFromFile loads, decrypts, and decompresses the data from a file.
func (fm *FileManager) LoadFromFile(filename string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	decryptedData, err := fm.encryption.Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	return fm.compression.Decompress(decryptedData)
}

// GenerateHash generates a SHA-256 hash of the given data.
func GenerateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
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
