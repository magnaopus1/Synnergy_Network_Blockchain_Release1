package metrics

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"github.com/prometheus/client_golang/prometheus"
)

// ThresholdAdjuster dynamically adjusts alert thresholds based on metrics data.
type ThresholdAdjuster struct {
	thresholds    map[string]float64
	thresholdsMux sync.RWMutex
	password      []byte
}

// NewThresholdAdjuster creates a new ThresholdAdjuster.
func NewThresholdAdjuster(password []byte) *ThresholdAdjuster {
	return &ThresholdAdjuster{
		thresholds: make(map[string]float64),
		password:   password,
	}
}

// SetThreshold sets the alert threshold for a specific metric.
func (ta *ThresholdAdjuster) SetThreshold(metricName string, value float64) {
	ta.thresholdsMux.Lock()
	defer ta.thresholdsMux.Unlock()

	ta.thresholds[metricName] = value
}

// GetThreshold gets the alert threshold for a specific metric.
func (ta *ThresholdAdjuster) GetThreshold(metricName string) (float64, bool) {
	ta.thresholdsMux.RLock()
	defer ta.thresholdsMux.RUnlock()

	value, exists := ta.thresholds[metricName]
	return value, exists
}

// ExportThresholds securely exports the alert thresholds using Argon2 and AES encryption.
func (ta *ThresholdAdjuster) ExportThresholds() ([]byte, error) {
	ta.thresholdsMux.RLock()
	defer ta.thresholdsMux.RUnlock()

	data, err := json.Marshal(ta.thresholds)
	if err != nil {
		return nil, err
	}

	return ta.encryptData(data)
}

// ImportThresholds securely imports the alert thresholds using Argon2 and AES encryption.
func (ta *ThresholdAdjuster) ImportThresholds(encryptedData []byte) error {
	data, err := ta.decryptData(encryptedData)
	if err != nil {
		return err
	}

	var thresholds map[string]float64
	if err := json.Unmarshal(data, &thresholds); err != nil {
		return err
	}

	ta.thresholdsMux.Lock()
	defer ta.thresholdsMux.Unlock()

	ta.thresholds = thresholds
	return nil
}

func (ta *ThresholdAdjuster) encryptData(data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(ta.password, salt, 1, 64*1024, 4, 32)
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

	return append(salt, ciphertext...), nil
}

func (ta *ThresholdAdjuster) decryptData(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key := argon2.IDKey(ta.password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// AdjustThresholds dynamically adjusts the thresholds based on metrics data.
func (ta *ThresholdAdjuster) AdjustThresholds(metricName string, adjustmentFactor float64) {
	metricValue := getMetricValue(metricName)

	ta.thresholdsMux.Lock()
	defer ta.thresholdsMux.Unlock()

	for name, value := range ta.thresholds {
		if metricValue > value {
			ta.thresholds[name] = value * adjustmentFactor
		} else {
			ta.thresholds[name] = value / adjustmentFactor
		}
	}
}

func getMetricValue(metricName string) float64 {
	// Placeholder function to get metric values.
	// This should interface with the Prometheus client to get real metrics.
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: metricName,
		Help: "Placeholder metric",
	})
	metric.Set(1.0)
	return metric.Get()
}
