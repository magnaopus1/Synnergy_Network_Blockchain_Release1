package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

// DeploymentManager handles automated deployment tasks
type DeploymentManager struct {
	mutex        sync.Mutex
	deployments  map[string]*Deployment
	encryptionKey []byte
}

// Deployment represents a deployment task
type Deployment struct {
	ID        string
	Status    string
	Logs      []string
	StartedAt string
	FinishedAt string
}

// NewDeploymentManager creates a new DeploymentManager
func NewDeploymentManager(encryptionKey string) *DeploymentManager {
	return &DeploymentManager{
		deployments:  make(map[string]*Deployment),
		encryptionKey: []byte(encryptionKey),
	}
}

// StartDeployment initiates a new deployment task
func (dm *DeploymentManager) StartDeployment(id, scriptPath string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if _, exists := dm.deployments[id]; exists {
		return errors.New("deployment already exists")
	}

	deployment := &Deployment{
		ID:        id,
		Status:    "started",
		StartedAt: getCurrentTime(),
	}

	dm.deployments[id] = deployment
	go dm.runDeployment(id, scriptPath)
	return nil
}

// runDeployment runs the deployment script and updates the status
func (dm *DeploymentManager) runDeployment(id, scriptPath string) {
	dm.mutex.Lock()
	deployment := dm.deployments[id]
	dm.mutex.Unlock()

	cmd := exec.Command("/bin/sh", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		deployment.Status = "failed"
		deployment.Logs = append(deployment.Logs, string(output))
		log.Printf("Deployment %s failed: %s", id, err)
	} else {
		deployment.Status = "completed"
		deployment.Logs = append(deployment.Logs, string(output))
		deployment.FinishedAt = getCurrentTime()
		log.Printf("Deployment %s completed successfully", id)
	}

	dm.mutex.Lock()
	dm.deployments[id] = deployment
	dm.mutex.Unlock()
}

// GetDeploymentStatus returns the status of a deployment
func (dm *DeploymentManager) GetDeploymentStatus(id string) (*Deployment, error) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	deployment, exists := dm.deployments[id]
	if !exists {
		return nil, errors.New("deployment not found")
	}

	return deployment, nil
}

// Encrypt encrypts data using AES
func (dm *DeploymentManager) Encrypt(data string) (string, error) {
	block, err := aes.NewCipher(dm.encryptionKey)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES
func (dm *DeploymentManager) Decrypt(encryptedData string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Helper function to get the current time
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// Additional methods and features can be added as needed for extending functionality
