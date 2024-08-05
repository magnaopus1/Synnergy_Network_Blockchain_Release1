package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ipfs/go-ipfs-api"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// OptimizedStorageSolutions struct to manage storage solutions
type OptimizedStorageSolutions struct {
	IPFSClient *shell.Shell
	LocalPath  string
}

// NewOptimizedStorageSolutions initializes a new OptimizedStorageSolutions instance
func NewOptimizedStorageSolutions(ipfsAPIURL, localPath string) *OptimizedStorageSolutions {
	return &OptimizedStorageSolutions{
		IPFSClient: shell.NewShell(ipfsAPIURL),
		LocalPath:  localPath,
	}
}

// UploadToIPFS uploads data to IPFS and returns the IPFS hash
func (oss *OptimizedStorageSolutions) UploadToIPFS(data []byte) (string, error) {
	hash, err := oss.IPFSClient.Add(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to upload to IPFS: %v", err)
	}
	return hash, nil
}

// DownloadFromIPFS downloads data from IPFS using the provided hash
func (oss *OptimizedStorageSolutions) DownloadFromIPFS(hash string) ([]byte, error) {
	reader, err := oss.IPFSClient.Cat(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to download from IPFS: %v", err)
	}
	defer reader.Close()

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from IPFS: %v", err)
	}
	return data, nil
}

// SaveLocally saves data to the local file system
func (oss *OptimizedStorageSolutions) SaveLocally(filename string, data []byte) error {
	filepath := oss.LocalPath + "/" + filename
	err := ioutil.WriteFile(filepath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to save data locally: %v", err)
	}
	return nil
}

// LoadLocally loads data from the local file system
func (oss *OptimizedStorageSolutions) LoadLocally(filename string) ([]byte, error) {
	filepath := oss.LocalPath + "/" + filename
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to load data locally: %v", err)
	}
	return data, nil
}

// EncryptData encrypts data using the specified encryption algorithm
func EncryptData(data []byte, key []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "argon2":
		salt := []byte("somesalt")
		hashedData := argon2.Key(data, salt, 1, 64*1024, 4, 32)
		return hashedData, nil
	case "scrypt":
		salt := []byte("somesalt")
		hashedData, err := scrypt.Key(data, salt, 16384, 8, 1, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data with scrypt: %v", err)
		}
		return hashedData, nil
	default:
		return nil, errors.New("unsupported encryption algorithm")
	}
}

// DecryptData decrypts data using the specified encryption algorithm
func DecryptData(encryptedData []byte, key []byte, algorithm string) ([]byte, error) {
	// In this example, we don't implement decryption as both argon2 and scrypt are one-way functions.
	// You should replace this logic with the appropriate decryption method if using a reversible encryption algorithm.
	return nil, errors.New("decryption not implemented for one-way encryption algorithms")
}

// StoreMetadata stores metadata as JSON to IPFS
func (oss *OptimizedStorageSolutions) StoreMetadata(metadata interface{}) (string, error) {
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %v", err)
	}

	hash, err := oss.UploadToIPFS(data)
	if err != nil {
		return "", fmt.Errorf("failed to store metadata on IPFS: %v", err)
	}
	return hash, nil
}

// RetrieveMetadata retrieves metadata from IPFS
func (oss *OptimizedStorageSolutions) RetrieveMetadata(hash string) (map[string]interface{}, error) {
	data, err := oss.DownloadFromIPFS(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve metadata from IPFS: %v", err)
	}

	var metadata map[string]interface{}
	err = json.Unmarshal(data, &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %v", err)
	}
	return metadata, nil
}
