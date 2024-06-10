package maintainance

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/synthron_blockchain/crypto/aes"
)

// UpdateManager handles the automated update processes.
type UpdateManager struct {
	UpdateServerURL string
	EncryptionKey   []byte
}

// NewUpdateManager creates a new instance of UpdateManager with the necessary configurations.
func NewUpdateManager(serverURL string, key []byte) *UpdateManager {
	return &UpdateManager{
		UpdateServerURL: serverURL,
		EncryptionKey:   key,
	}
}

// FetchUpdate checks for the latest update from the update server.
func (um *UpdateManager) FetchUpdate() ([]byte, error) {
	resp, err := http.Get(um.UpdateServerURL + "/latest")
	if err != nil {
		return nil, fmt.Errorf("error fetching update: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch update: status code %d", resp.StatusCode)
	}

	updateData, err := os.ReadFile(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading update data: %v", err)
	}

	return updateData, nil
}

// ApplyUpdate applies the downloaded update file.
func (um *UpdateManager) ApplyUpdate(data []byte) error {
	// Decrypt data if necessary
	decryptedData, err := aes.Decrypt(data, um.EncryptionKey)
	if err != nil {
		return fmt.Errorf("error decrypting update data: %v", err)
	}

	// Simulate applying the update
	fmt.Println("Applying update: ", decryptedData)
	// Actual update application logic goes here

	return nil
}

// ScheduleUpdates configures the periodic checking and application of updates.
func (um *UpdateManager) ScheduleUpdates(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("Checking for updates...")
		updateData, err := um.FetchUpdate()
		if err != nil {
			fmt.Println("Error fetching update:", err)
			continue
		}

		if err := um.ApplyUpdate(updateData); err != nil {
			fmt.Println("Error applying update:", err)
			continue
		}

		fmt.Println("Update applied successfully")
	}
}

func main() {
	// Example setup
	updateManager := NewUpdateManager("https://update.synthron_blockchain.com", []byte("your-256-bit-secret"))
	// Schedule updates to check every 24 hours
	updateManager.ScheduleUpdates(24 * time.Hour)
}
