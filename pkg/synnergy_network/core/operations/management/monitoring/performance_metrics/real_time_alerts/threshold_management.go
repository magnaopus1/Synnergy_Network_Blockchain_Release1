package performance_metrics

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Threshold represents a threshold for performance metrics
type Threshold struct {
	ID          string    `json:"id"`
	Metric      string    `json:"metric"`
	Condition   string    `json:"condition"`
	Value       float64   `json:"value"`
	Triggered   bool      `json:"triggered"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// ThresholdService handles threshold management logic
type ThresholdService struct {
	Thresholds []Threshold
	Mutex      sync.Mutex
	Storage    string // File path for persisting thresholds
}

// NewThresholdService creates a new ThresholdService
func NewThresholdService(storage string) *ThresholdService {
	service := &ThresholdService{
		Thresholds: []Threshold{},
		Storage:    storage,
	}
	service.loadThresholds()
	return service
}

// CreateThreshold adds a new threshold to the system
func (service *ThresholdService) CreateThreshold(metric, condition string, value float64, description string) {
	service.Mutex.Lock()
	defer service.Mutex.Unlock()

	threshold := Threshold{
		ID:          generateID(),
		Metric:      metric,
		Condition:   condition,
		Value:       value,
		Triggered:   false,
		Timestamp:   time.Now(),
		Description: description,
	}

	service.Thresholds = append(service.Thresholds, threshold)
	service.saveThresholds()
}

// GetThresholds retrieves all thresholds
func (service *ThresholdService) GetThresholds() []Threshold {
	service.Mutex.Lock()
	defer service.Mutex.Unlock()

	return service.Thresholds
}

// TriggerThreshold triggers a threshold based on given conditions
func (service *ThresholdService) TriggerThreshold(id string) error {
	service.Mutex.Lock()
	defer service.Mutex.Unlock()

	for i, threshold := range service.Thresholds {
		if threshold.ID == id {
			service.Thresholds[i].Triggered = true
			service.Thresholds[i].Timestamp = time.Now()
			service.saveThresholds()
			return nil
		}
	}
	return errors.New("threshold not found")
}

// saveThresholds saves the current thresholds to the storage file
func (service *ThresholdService) saveThresholds() {
	data, err := json.Marshal(service.Thresholds)
	if err != nil {
		log.Printf("Error marshaling thresholds: %v", err)
		return
	}

	encryptedData, err := encryptData(data)
	if err != nil {
		log.Printf("Error encrypting thresholds: %v", err)
		return
	}

	err = os.WriteFile(service.Storage, encryptedData, 0644)
	if err != nil {
		log.Printf("Error writing thresholds to file: %v", err)
	}
}

// loadThresholds loads the thresholds from the storage file
func (service *ThresholdService) loadThresholds() {
	data, err := os.ReadFile(service.Storage)
	if err != nil {
		log.Printf("Error reading thresholds from file: %v", err)
		return
	}

	decryptedData, err := decryptData(data)
	if err != nil {
		log.Printf("Error decrypting thresholds: %v", err)
		return
	}

	err = json.Unmarshal(decryptedData, &service.Thresholds)
	if err != nil {
		log.Printf("Error unmarshaling thresholds: %v", err)
	}
}

// generateID generates a unique identifier for thresholds
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// encryptData encrypts the given data using AES encryption
func encryptData(data []byte) ([]byte, error) {
	key := argon2.IDKey([]byte("password"), []byte("salt"), 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// decryptData decrypts the given data using AES decryption
func decryptData(data []byte) ([]byte, error) {
	key := argon2.IDKey([]byte("password"), []byte("salt"), 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// MonitorThreshold continuously monitors a specific metric and triggers thresholds based on predefined conditions
func (service *ThresholdService) MonitorThreshold(metric string, getMetricValue func() float64) {
	for {
		value := getMetricValue()
		service.Mutex.Lock()
		for _, threshold := range service.Thresholds {
			if threshold.Metric == metric && !threshold.Triggered {
				switch threshold.Condition {
				case "greater_than":
					if value > threshold.Value {
						service.TriggerThreshold(threshold.ID)
					}
				case "less_than":
					if value < threshold.Value {
						service.TriggerThreshold(threshold.ID)
					}
				}
			}
		}
		service.Mutex.Unlock()
		time.Sleep(1 * time.Minute) // Adjust the frequency of checks as needed
	}
}
