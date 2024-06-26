package privacymanagement

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"synthron_blockchain_final/pkg/layer0/core/identity_services/privacy_management/blockchain"

	"github.com/google/uuid"
)

// DataMasker manages the encryption and decryption processes for user data.
type DataMasker struct {
	encryptionKey []byte
}

// NewDataMasker creates a new instance of DataMasker with a provided encryption key.
func NewDataMasker(key []byte) *DataMasker {
	return &DataMasker{
		encryptionKey: key,
	}
}

// EncryptData masks the given data using AES encryption.
func (dm *DataMasker) EncryptData(data string) (string, error) {
	block, err := aes.NewCipher(dm.encryptionKey)
	if err != nil {
		return "", err
	}

	b := base64.StdEncoding.EncodeToString([]byte(data))
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData uncovers the original data from the encrypted string.
func (dm *DataMasker) DecryptData(encryptedData string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dm.encryptionKey)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", err
	}

	return string(decodedData), nil
}

// StoreEncryptedData saves encrypted user data in the blockchain with metadata.
func (dm *DataMasker) StoreEncryptedData(userID, data string) (string, error) {
	encryptedData, err := dm.EncryptData(data)
	if err != nil {
		return "", err
	}

	dataID := uuid.NewString()
	metadata := map[string]string{
		"userID":        userID,
		"encryptedData": encryptedData,
	}

	if err := blockchain.StoreData(dataID, metadata); err != nil {
		return "", err
	}

	return dataID, nil
}

// RetrieveAndDecryptData fetches and decrypts data from the blockchain.
func (dm *DataMasker) RetrieveAndDecryptData(dataID string) (string, error) {
	metadata, err := blockchain.RetrieveData(dataID)
	if err != nil {
		return "", err
	}

	encryptedData, ok := metadata["encryptedData"]
	if !ok {
		return "", errors.New("encrypted data not found in metadata")
	}

	return dm.DecryptData(encryptedData)
}
