package compression

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// TransactionCompression provides functionalities for transaction compression and encryption.
type TransactionCompression struct {
	key []byte
}

// NewTransactionCompression initializes the TransactionCompression with a passphrase.
func NewTransactionCompression(passphrase string) (*TransactionCompression, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &TransactionCompression{
		key: key,
	}, nil
}

// CompressAndEncryptTransaction compresses and encrypts the given transaction data.
func (tc *TransactionCompression) CompressAndEncryptTransaction(data []byte) ([]byte, error) {
	compressedData, err := compress(data)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encrypt(compressedData, tc.key)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptAndDecompressTransaction decrypts and decompresses the given transaction data.
func (tc *TransactionCompression) DecryptAndDecompressTransaction(encryptedData []byte) ([]byte, error) {
	decryptedData, err := decrypt(encryptedData, tc.key)
	if err != nil {
		return nil, err
	}

	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
}

// SaveTransactionToFile compresses, encrypts, and saves the transaction data to a file.
func (tc *TransactionCompression) SaveTransactionToFile(filename string, data []byte) error {
	encryptedData, err := tc.CompressAndEncryptTransaction(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadTransactionFromFile loads, decrypts, and decompresses the transaction data from a file.
func (tc *TransactionCompression) LoadTransactionFromFile(filename string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := tc.DecryptAndDecompressTransaction(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// compress compresses the given data using zlib.
func compress(data []byte) ([]byte, error) {
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

// decompress decompresses the given data using zlib.
func decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
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

// SaveAsGZIP compresses and saves the transaction data in GZIP format.
func (tc *TransactionCompression) SaveAsGZIP(filename string, data []byte) error {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return ioutil.WriteFile(filename, b.Bytes(), 0644)
}

// LoadFromGZIP loads and decompresses the transaction data from a GZIP file.
func (tc *TransactionCompression) LoadFromGZIP(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ioutil.ReadAll(r)
}

// GenerateTransactionHash generates a SHA-256 hash of the given transaction data.
func GenerateTransactionHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// VerifyTransactionIntegrity verifies the integrity of the transaction data by comparing its hash.
func VerifyTransactionIntegrity(data []byte, hash string) bool {
	return GenerateTransactionHash(data) == hash
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// CreateTransactionSnapshot creates a snapshot of the current transaction and saves it to a file.
func (tc *TransactionCompression) CreateTransactionSnapshot(filename string, transactionData []byte) error {
	err := tc.SaveTransactionToFile(filename, transactionData)
	if err != nil {
		return err
	}

	hash := GenerateTransactionHash(transactionData)
	hashFile := filename + ".hash"
	err = os.WriteFile(hashFile, []byte(hash), 0644)
	if err != nil {
		return err
	}

	return nil
}

// VerifyTransactionSnapshot verifies the integrity of the transaction snapshot file.
func (tc *TransactionCompression) VerifyTransactionSnapshot(filename string) (bool, error) {
	transactionData, err := tc.LoadTransactionFromFile(filename)
	if err != nil {
		return false, err
	}

	hashFile := filename + ".hash"
	storedHash, err := os.ReadFile(hashFile)
	if err != nil {
		return false, err
	}

	return VerifyTransactionIntegrity(transactionData, string(storedHash)), nil
}

// SaveAsJSON compresses, encrypts, and saves the transaction data in JSON format.
func (tc *TransactionCompression) SaveAsJSON(filename string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return tc.SaveTransactionToFile(filename, jsonData)
}

// LoadFromJSON loads, decrypts, and decompresses the transaction data from a JSON file.
func (tc *TransactionCompression) LoadFromJSON(filename string, result interface{}) error {
	data, err := tc.LoadTransactionFromFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, result)
}
