package resource_optimization

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
)

// DataCompression provides methods to compress and decompress data using gzip.
type DataCompression struct {
	key []byte
}

// NewDataCompression creates a new instance of DataCompression.
func NewDataCompression(key []byte) *DataCompression {
	return &DataCompression{key: key}
}

// Compress compresses the given data using gzip.
func (dc *DataCompression) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress decompresses the given gzip-compressed data.
func (dc *DataCompression) Decompress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)
	gz, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return ioutil.ReadAll(gz)
}

// Encrypt encrypts the given data using AES.
func (dc *DataCompression) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(dc.key)
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
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given data using AES.
func (dc *DataCompression) Decrypt(data string) ([]byte, error) {
	block, err := aes.NewCipher(dc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CompressAndEncrypt compresses and then encrypts the data.
func (dc *DataCompression) CompressAndEncrypt(data []byte) (string, error) {
	compressedData, err := dc.Compress(data)
	if err != nil {
		return "", err
	}
	return dc.Encrypt(compressedData)
}

// DecryptAndDecompress decrypts and then decompresses the data.
func (dc *DataCompression) DecryptAndDecompress(data string) ([]byte, error) {
	decryptedData, err := dc.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return dc.Decompress(decryptedData)
}

// Example usage:
func main() {
	key := []byte("myverystrongpasswordo32bitlength")
	data := []byte("The quick brown fox jumps over the lazy dog")

	dc := NewDataCompression(key)
	encryptedData, err := dc.CompressAndEncrypt(data)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Encrypted and compressed data: %s\n", encryptedData)

	decryptedData, err := dc.DecryptAndDecompress(encryptedData)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decrypted and decompressed data: %s\n", decryptedData)
}
