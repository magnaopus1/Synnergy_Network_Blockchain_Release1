package ci_pipelines

import (
	"fmt"
	"log"
	"os/exec"
	"time"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"golang.org/x/crypto/scrypt"
)

// BuildConfig holds the configuration for the build automation process
type BuildConfig struct {
	SourcePath         string
	OutputPath         string
	EncryptionKey      string
	BuildCommand       string
	CleanupOldBuilds   bool
	MaxBuildAge        time.Duration
	VersioningEnabled  bool
	MonitoringEnabled  bool
}

// BuildArtifact represents a build artifact
type BuildArtifact struct {
	Name      string
	Path      string
	Timestamp time.Time
}

// AutomatedBuild handles the automation of the build process
func AutomatedBuild(config BuildConfig) error {
	log.Println("Starting automated build process...")

	// Step 1: Execute the build command
	cmd := exec.Command("sh", "-c", config.BuildCommand)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build command failed: %v, output: %s", err, output)
	}
	log.Printf("Build command output: %s\n", output)

	// Step 2: Encrypt the build output
	artifactPath := fmt.Sprintf("%s/build_output_%d.tar.gz", config.OutputPath, time.Now().Unix())
	err = encryptAndSaveBuildOutput(artifactPath, config.SourcePath, config.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt and save build output: %v", err)
	}

	// Step 3: Clean up old builds if enabled
	if config.CleanupOldBuilds {
		err = cleanupOldBuilds(config.OutputPath, config.MaxBuildAge)
		if err != nil {
			return fmt.Errorf("failed to clean up old builds: %v", err)
		}
	}

	// Step 4: Monitor build output if enabled
	if config.MonitoringEnabled {
		err = monitorBuildOutput(config.OutputPath)
		if err != nil {
			return fmt.Errorf("failed to monitor build output: %v", err)
		}
	}

	log.Println("Automated build process completed successfully.")
	return nil
}

// encryptAndSaveBuildOutput encrypts the build output and saves it to the specified path
func encryptAndSaveBuildOutput(outputPath, sourcePath, encryptionKey string) error {
	data, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %v", err)
	}

	encryptedData, err := encryptData(data, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	err = ioutil.WriteFile(outputPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data to file: %v", err)
	}

	return nil
}

// encryptData encrypts the given data using AES encryption with a key derived from the provided passphrase
func encryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// cleanupOldBuilds removes old build artifacts based on the specified maximum age
func cleanupOldBuilds(outputPath string, maxBuildAge time.Duration) error {
	files, err := ioutil.ReadDir(outputPath)
	if err != nil {
		return fmt.Errorf("failed to read output directory: %v", err)
	}

	for _, file := range files {
		if time.Since(file.ModTime()) > maxBuildAge {
			err = os.Remove(filepath.Join(outputPath, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to remove old build file: %v", err)
			}
		}
	}

	return nil
}

// monitorBuildOutput sets up monitoring for the build output
func monitorBuildOutput(outputPath string) error {
	log.Printf("Monitoring build output at: %s\n", outputPath)
	// Implement monitoring logic here, potentially integrating with external tools
	return nil
}

// decryptData decrypts the given data using AES decryption with a key derived from the provided passphrase
func decryptData(data []byte, passphrase string) ([]byte, error) {
	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}
