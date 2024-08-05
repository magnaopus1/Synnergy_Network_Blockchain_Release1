package diagnostic_tools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// SoftwareUpdateManager manages software updates for the blockchain network.
type SoftwareUpdateManager struct {
	updateURL     string
	encryptionKey []byte
}

// NewSoftwareUpdateManager creates a new instance of SoftwareUpdateManager.
func NewSoftwareUpdateManager(updateURL string, encryptionKey []byte) *SoftwareUpdateManager {
	return &SoftwareUpdateManager{
		updateURL:     updateURL,
		encryptionKey: encryptionKey,
	}
}

// FetchUpdate fetches the latest software update.
func (m *SoftwareUpdateManager) FetchUpdate() ([]byte, error) {
	resp, err := http.Get(m.updateURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch update")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// EncryptData encrypts the given data using AES.
func (m *SoftwareUpdateManager) EncryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(m.encryptionKey)
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

// DecryptData decrypts the given data using AES.
func (m *SoftwareUpdateManager) DecryptData(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(m.encryptionKey)
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

// ScheduleUpdate schedules the software update to be applied at the specified time.
func (m *SoftwareUpdateManager) ScheduleUpdate(updateTime time.Time, updateData []byte) error {
	// This example uses a basic timer for scheduling.
	// For real-world applications, use a job scheduler or a distributed task queue.

	timeUntilUpdate := time.Until(updateTime)
	if timeUntilUpdate < 0 {
		return errors.New("update time is in the past")
	}

	time.AfterFunc(timeUntilUpdate, func() {
		err := m.ApplyUpdate(updateData)
		if err != nil {
			log.Println("Failed to apply update:", err)
		}
	})

	return nil
}

// ApplyUpdate applies the software update to the system.
func (m *SoftwareUpdateManager) ApplyUpdate(updateData []byte) error {
	// Placeholder for actual update logic
	// In a real-world scenario, this might involve applying patches, updating binaries, etc.

	log.Println("Applying software update...")
	// Example of update logic
	err := os.WriteFile("software_update.bin", updateData, 0644)
	if err != nil {
		return err
	}

	log.Println("Software update applied successfully.")
	return nil
}

// GenerateEncryptionKey generates a new encryption key using scrypt.
func GenerateEncryptionKey(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// NotifyNodes sends a notification to all nodes about the software update.
func (m *SoftwareUpdateManager) NotifyNodes(updateInfo map[string]string) error {
	updateInfoJSON, err := json.Marshal(updateInfo)
	if err != nil {
		return err
	}

	// Placeholder URL for nodes' notification endpoint
	notificationURL := "http://node.network/notify_update"
	resp, err := http.Post(notificationURL, "application/json", bytes.NewBuffer(updateInfoJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to notify nodes")
	}

	log.Println("Nodes notified successfully about the update.")
	return nil
}
