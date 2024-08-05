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

// StateCompression provides functionalities for state compression and encryption.
type StateCompression struct {
	key []byte
}

// NewStateCompression initializes the StateCompression with a passphrase.
func NewStateCompression(passphrase string) (*StateCompression, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &StateCompression{
		key: key,
	}, nil
}

// CompressAndEncryptState compresses and encrypts the given state data.
func (sc *StateCompression) CompressAndEncryptState(data []byte) ([]byte, error) {
	compressedData, err := compress(data)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encrypt(compressedData, sc.key)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptAndDecompressState decrypts and decompresses the given state data.
func (sc *StateCompression) DecryptAndDecompressState(encryptedData []byte) ([]byte, error) {
	decryptedData, err := decrypt(encryptedData, sc.key)
	if err != nil {
		return nil, err
	}

	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
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

// SaveStateToFile compresses, encrypts, and saves the state data to a file.
func (sc *StateCompression) SaveStateToFile(filename string, data []byte) error {
	encryptedData, err := sc.CompressAndEncryptState(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadStateFromFile loads, decrypts, and decompresses the state data from a file.
func (sc *StateCompression) LoadStateFromFile(filename string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := sc.DecryptAndDecompressState(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GenerateStateHash generates a SHA-256 hash of the given state data.
func GenerateStateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// VerifyStateIntegrity verifies the integrity of the state data by comparing its hash.
func VerifyStateIntegrity(data []byte, hash string) bool {
	return GenerateStateHash(data) == hash
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// CreateStateSnapshot creates a snapshot of the current state and saves it to a file.
func (sc *StateCompression) CreateStateSnapshot(filename string, stateData []byte) error {
	err := sc.SaveStateToFile(filename, stateData)
	if err != nil {
		return err
	}

	hash := GenerateStateHash(stateData)
	hashFile := filename + ".hash"
	err = os.WriteFile(hashFile, []byte(hash), 0644)
	if err != nil {
		return err
	}

	return nil
}

// VerifyStateSnapshot verifies the integrity of the state snapshot file.
func (sc *StateCompression) VerifyStateSnapshot(filename string) (bool, error) {
	stateData, err := sc.LoadStateFromFile(filename)
	if err != nil {
		return false, err
	}

	hashFile := filename + ".hash"
	storedHash, err := os.ReadFile(hashFile)
	if err != nil {
		return false, err
	}

	return VerifyStateIntegrity(stateData, string(storedHash)), nil
}
