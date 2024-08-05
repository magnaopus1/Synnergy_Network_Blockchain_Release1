package ai_powered_anomaly_detection

import (
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/synnergy_network/core/testnet/ai_powered_anomaly_detection/data_collection"
	"golang.org/x/crypto/argon2"
)

// RealTimeDetector represents the real-time anomaly detection system
type RealTimeDetector struct {
	Collector      *data_collection.NetworkMetricsCollector
	DetectionModel *AnomalyDetectionModel
	AlertHandler   AlertHandler
	EncryptionKey  []byte
	Threshold      float64
}

// AnomalyDetectionModel represents the model used for detecting anomalies
type AnomalyDetectionModel struct {
	ModelData []byte
}

// AlertHandler is an interface for handling alerts
type AlertHandler interface {
	HandleAlert(anomaly Anomaly) error
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Timestamp time.Time `json:"timestamp"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Details   string    `json:"details"`
}

// NewRealTimeDetector creates a new RealTimeDetector instance
func NewRealTimeDetector(collector *data_collection.NetworkMetricsCollector, alertHandler AlertHandler, encryptionKey []byte, threshold float64) *RealTimeDetector {
	return &RealTimeDetector{
		Collector:     collector,
		AlertHandler:  alertHandler,
		EncryptionKey: encryptionKey,
		Threshold:     threshold,
	}
}

// DetectAndHandleAnomalies detects anomalies in real-time and handles them using the alert handler
func (detector *RealTimeDetector) DetectAndHandleAnomalies() error {
	metrics, err := detector.Collector.GetMetrics()
	if err != nil {
		return err
	}

	for _, metric := range metrics {
		if metric.Value > detector.Threshold {
			anomaly := Anomaly{
				Timestamp: metric.Timestamp,
				Metric:    metric.Type,
				Value:     metric.Value,
				Details:   "Anomaly detected based on threshold",
			}
			err := detector.AlertHandler.HandleAlert(anomaly)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// AnomalyDetectionModel methods for training and updating
func (model *AnomalyDetectionModel) Train(data []byte, key []byte) error {
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return err
	}
	model.ModelData = encryptedData
	return nil
}

func (model *AnomalyDetectionModel) Update(data []byte, key []byte) error {
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return err
	}
	model.ModelData = append(model.ModelData, encryptedData...)
	return nil
}

// Encrypts data using Argon2-derived key
func encryptData(data []byte, key []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := net.Read(salt)
	if err != nil {
		return nil, err
	}
	derivedKey := argon2.IDKey(key, salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypts data using Argon2-derived key
func decryptData(data []byte, key []byte) ([]byte, error) {
	salt := data[:16]
	derivedKey := argon2.IDKey(key, salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(derivedKey)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// AlertHandler implementation for logging anomalies
type LoggingAlertHandler struct {
	LogFilePath string
}

// NewLoggingAlertHandler creates a new LoggingAlertHandler instance
func NewLoggingAlertHandler(logFilePath string) *LoggingAlertHandler {
	return &LoggingAlertHandler{
		LogFilePath: logFilePath,
	}
}

// HandleAlert logs the anomaly to a file
func (handler *LoggingAlertHandler) HandleAlert(anomaly Anomaly) error {
	file, err := os.OpenFile(handler.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	anomalyData, err := json.Marshal(anomaly)
	if err != nil {
		return err
	}
	_, err = file.WriteString(string(anomalyData) + "\n")
	return err
}
