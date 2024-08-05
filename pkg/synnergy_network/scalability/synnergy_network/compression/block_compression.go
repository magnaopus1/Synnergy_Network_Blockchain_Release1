package compression

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// BlockCompression provides functionalities for block compression and encryption.
type BlockCompression struct {
	key []byte
}

// NewBlockCompression initializes the BlockCompression with a passphrase.
func NewBlockCompression(passphrase string) (*BlockCompression, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &BlockCompression{
		key: key,
	}, nil
}

// CompressAndEncryptBlock compresses and encrypts the given data block.
func (bc *BlockCompression) CompressAndEncryptBlock(data []byte) ([]byte, error) {
	compressedData, err := compress(data)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encrypt(compressedData, bc.key)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptAndDecompressBlock decrypts and decompresses the given data block.
func (bc *BlockCompression) DecryptAndDecompressBlock(encryptedData []byte) ([]byte, error) {
	decryptedData, err := decrypt(encryptedData, bc.key)
	if err != nil {
		return nil, err
	}

	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
}

// compress compresses the given data using gzip.
func compress(data []byte) ([]byte, error) {
	var b io.Writer
	buf := &bytes.Buffer{}
	b = gzip.NewWriter(buf)
	if _, err := b.Write(data); err != nil {
		return nil, err
	}
	if err := b.(*gzip.Writer).Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decompress decompresses the given data using gzip.
func decompress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	decompressedData, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

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

// SaveBlockToFile saves the encrypted block data to a file.
func (bc *BlockCompression) SaveBlockToFile(filename string, data []byte) error {
	encryptedData, err := bc.CompressAndEncryptBlock(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadBlockFromFile loads and decrypts block data from a file.
func (bc *BlockCompression) LoadBlockFromFile(filename string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := bc.DecryptAndDecompressBlock(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GenerateBlockHash generates a SHA-256 hash of the given block data.
func GenerateBlockHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// VerifyBlockIntegrity verifies the integrity of the block data by comparing its hash.
func VerifyBlockIntegrity(data []byte, hash string) bool {
	return GenerateBlockHash(data) == hash
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}
