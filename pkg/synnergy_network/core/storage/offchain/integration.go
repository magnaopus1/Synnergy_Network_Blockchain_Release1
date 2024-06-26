package offchain

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// OffchainStorageManager handles interactions with offchain storage services.
type OffchainStorageManager struct {
	s3Service *s3.S3
	bucket    string
}

// NewOffchainStorageManager creates a new instance of OffchainStorageManager with specified S3 bucket.
func NewOffcockainStorageManager(bucket string) (*OffchainStorageManager, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		return nil, err
	}

	return &OffchainStorageManager{
		s3Service: s3.New(sess),
		bucket:    bucket,
	}, nil
}

// StoreData securely stores data in the configured off-chain storage.
func (m *OffchainStorageManager) StoreData(key string, data []byte) error {
	// Encrypt the data before storing it off-chain
	encryptedData, err := encryptData(data)
	if err != nil {
		return err
	}

	_, err = m.s3Service.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(m.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(encryptedData),
	})
	return err
}

// RetrieveData retrieves and decrypts data from the off-chain storage.
func (m *OffchainStorageManager) RetrieveData(key string) ([]byte, error) {
	resp, err := m.s3Service.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(m.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return decryptData(encryptedData)
}

// encryptData uses AES encryption to securely encrypt data before storage.
func encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(crypto.GenerateKey())
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
	return ciphertext, nil
}

// decryptData decrypts data using AES encryption.
func decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(crypto.GenerateNewKey())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

