package distributed_cloud_storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// CloudStorageService encapsulates the client for cloud storage operations.
type CloudStorageService struct {
	s3Client *s3.S3
}

// NewCloudStorageService initializes a new S3 client to interact with cloud storage.
func NewCloudStorageService(sess *session.Session) *CloudStorageService {
	return &CloudStorageService{
		s3Client: s3.New(sess),
	}
}

// UploadFile encrypts and uploads a file to the cloud storage.
func (service *CloudStorageService) UploadFile(bucket, key string, data []byte) error {
	encryptedData, err := EncryptData(data)
	if err != nil {
		return err
	}

	_, err = service.s3Client.PutObject(&s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   bytes.NewReader(encryptedData),
	})
	if err != nil {
		return err
	}
	log.Println("File uploaded successfully to", bucket, "with key", key)
	return nil
}

// DownloadFile downloads and decrypts a file from the cloud storage.
func (service *CloudStorageService) DownloadFile(bucket, key string) ([]byte, error) {
	resp, err := service.s3Client.GetObject(&s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return DecryptData(encryptedData)
}

// EncryptData encrypts data using AES-GCM.
func EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte("your-32-byte-long-ultra-secure-key-here"))
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

	cipherData := gcm.Seal(nonce, nonce, data, nil)
	return cipherData, nil
}

// DecryptData decrypts data using AES-GCM.
func DecryptData(encryptedData []byte) ([]byte, error) {
	key := []byte("your-32-byte-long-ultra-secure-key-here")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plainData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
        return nil, err
	}
	return plainData, nil
}

