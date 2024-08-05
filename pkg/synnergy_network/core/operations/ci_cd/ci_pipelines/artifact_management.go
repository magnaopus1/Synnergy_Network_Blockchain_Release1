package ci_pipelines

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"github.com/synnergy_network/blockchain/core"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/blockchain/monitoring"
)

// ArtifactConfig holds the configuration for artifact management
type ArtifactConfig struct {
	StoragePath        string
	EncryptionKey      string
	RetentionPolicy    string
	BackupFrequency    time.Duration
	VersioningEnabled  bool
	MonitoringEnabled  bool
}

// StoreArtifact handles storing build artifacts securely
func StoreArtifact(config ArtifactConfig, artifactPath string) error {
	// Step 1: Read artifact data
	data, err := ioutil.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read artifact: %v", err)
	}

	// Step 2: Encrypt the artifact data
	encryptedData, err := encryptData(data, config.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt artifact: %v", err)
	}

	// Step 3: Save the encrypted data to storage
	storagePath := filepath.Join(config.StoragePath, filepath.Base(artifactPath))
	err = ioutil.WriteFile(storagePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write encrypted artifact: %v", err)
	}

	// Step 4: Apply retention policy
	err = applyRetentionPolicy(config)
	if err != nil {
		return fmt.Errorf("failed to apply retention policy: %v", err)
	}

	// Step 5: Monitor artifact storage if enabled
	if config.MonitoringEnabled {
		err = monitorArtifactStorage(config, storagePath)
		if err != nil {
			return fmt.Errorf("failed to monitor artifact storage: %v", err)
		}
	}

	log.Println("Artifact stored successfully.")
	return nil
}

// encryptData securely encrypts data using AES and Scrypt
func encryptData(data []byte, passphrase string) ([]byte, error) {
	salt, err := generateRandomBytes(16)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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

	nonce, err := generateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// generateRandomBytes generates random bytes for encryption
func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	return bytes, err
}

// applyRetentionPolicy applies the retention policy to the stored artifacts
func applyRetentionPolicy(config ArtifactConfig) error {
	// Implement logic to apply retention policies based on the config
	log.Println("Applying retention policy...")
	return nil
}

// monitorArtifactStorage sets up monitoring for the artifact storage
func monitorArtifactStorage(config ArtifactConfig, storagePath string) error {
	if config.MonitoringEnabled {
		monitoringData := monitoring.CollectData(config.StoragePath, storagePath)

		if len(monitoringData) == 0 {
			return fmt.Errorf("failed to collect monitoring data for artifact storage")
		}
		log.Printf("Monitoring data collected for artifact storage: %v\n", monitoringData)
	}
	return nil
}

// RetrieveArtifact handles retrieving build artifacts securely
func RetrieveArtifact(config ArtifactConfig, artifactName string) ([]byte, error) {
	// Step 1: Read encrypted artifact data from storage
	storagePath := filepath.Join(config.StoragePath, artifactName)
	encryptedData, err := ioutil.ReadFile(storagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted artifact: %v", err)
	}

	// Step 2: Decrypt the artifact data
	data, err := decryptData(encryptedData, config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt artifact: %v", err)
	}

	log.Println("Artifact retrieved successfully.")
	return data, nil
}

// decryptData securely decrypts data using AES and Scrypt
func decryptData(data []byte, passphrase string) ([]byte, error) {
	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// BackupArtifacts handles the backup of artifacts based on the backup frequency
func BackupArtifacts(config ArtifactConfig) error {
	backupPath := filepath.Join(config.StoragePath, "backup")
	err := os.MkdirAll(backupPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create backup directory: %v", err)
	}

	cmd := exec.Command("cp", "-r", config.StoragePath, backupPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to backup artifacts: %v, %s", err, output)
	}

	log.Println("Artifacts backed up successfully.")
	return nil
}

// VersionArtifact handles versioning of artifacts if versioning is enabled
func VersionArtifact(config ArtifactConfig, artifactPath string) error {
	if config.VersioningEnabled {
		versionedPath := filepath.Join(config.StoragePath, "versions", fmt.Sprintf("%s_%d", filepath.Base(artifactPath), time.Now().Unix()))
		err := os.MkdirAll(filepath.Dir(versionedPath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create versioned directory: %v", err)
		}

		err = exec.Command("cp", artifactPath, versionedPath).Run()
		if err != nil {
			return fmt.Errorf("failed to version artifact: %v", err)
		}

		log.Println("Artifact versioned successfully.")
	}
	return nil
}
