package predictive_maintenance

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/utils/encryption_utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/logging_utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/monitoring_utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/signature_utils"
)

// AnomalyDetection represents the structure for detecting anomalies in the IoT devices' data.
type AnomalyDetection struct {
	ID             string
	DeviceID       string
	Timestamp      time.Time
	RawData        string
	EncryptedData  string
	Signature      string
	AnomalyType    string
	Severity       string
	Status         string
	DetectionTime  time.Time
	ResolutionTime time.Time
}

// AnomalyRegistry maintains a list of detected anomalies.
type AnomalyRegistry struct {
	anomalies map[string]*AnomalyDetection
}

// NewAnomalyRegistry creates a new instance of AnomalyRegistry.
func NewAnomalyRegistry() *AnomalyRegistry {
	return &AnomalyRegistry{
		anomalies: make(map[string]*AnomalyDetection),
	}
}

// DetectAnomaly detects an anomaly in the device data and stores it in the registry.
func (ar *AnomalyRegistry) DetectAnomaly(deviceID, rawData, signature string) (*AnomalyDetection, error) {
	// Validate the signature
	valid, err := signature_utils.VerifySignature(rawData, signature, deviceID)
	if err != nil || !valid {
		return nil, errors.New("invalid data signature")
	}

	// Encrypt the raw data
	encryptedData, err := encryption_utils.EncryptData(rawData, deviceID)
	if err != nil {
		return nil, err
	}

	// Analyze the raw data to detect anomalies (mocked analysis here)
	anomalyType, severity := analyzeDataForAnomalies(rawData)

	anomaly := &AnomalyDetection{
		ID:            generateAnomalyID(),
		DeviceID:      deviceID,
		Timestamp:     time.Now(),
		RawData:       rawData,
		EncryptedData: encryptedData,
		Signature:     signature,
		AnomalyType:   anomalyType,
		Severity:      severity,
		Status:        "Detected",
		DetectionTime: time.Now(),
	}

	ar.anomalies[anomaly.ID] = anomaly
	logging_utils.LogInfo(fmt.Sprintf("Anomaly detected: %s, Severity: %s", anomalyType, severity))

	return anomaly, nil
}

// ResolveAnomaly marks an anomaly as resolved in the registry.
func (ar *AnomalyRegistry) ResolveAnomaly(anomalyID string) error {
	anomaly, exists := ar.anomalies[anomalyID]
	if !exists {
		return errors.New("anomaly not found")
	}

	anomaly.Status = "Resolved"
	anomaly.ResolutionTime = time.Now()
	logging_utils.LogInfo(fmt.Sprintf("Anomaly resolved: %s", anomalyID))

	return nil
}

// ListAnomalies lists all detected anomalies.
func (ar *AnomalyRegistry) ListAnomalies() []*AnomalyDetection {
	var anomalyList []*AnomalyDetection
	for _, anomaly := range ar.anomalies {
		anomalyList = append(anomalyList, anomaly)
	}
	return anomalyList
}

// GetAnomaly retrieves an anomaly by its ID.
func (ar *AnomalyRegistry) GetAnomaly(anomalyID string) (*AnomalyDetection, error) {
	anomaly, exists := ar.anomalies[anomalyID]
	if !exists {
		return nil, errors.New("anomaly not found")
	}
	return anomaly, nil
}

// SerializeAnomaly serializes the anomaly struct to JSON format.
func (a *AnomalyDetection) SerializeAnomaly() (string, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeAnomaly deserializes the JSON string to an anomaly struct.
func DeserializeAnomaly(data string) (*AnomalyDetection, error) {
	var anomaly AnomalyDetection
	err := json.Unmarshal([]byte(data), &anomaly)
	if err != nil {
		return nil, err
	}
	return &anomaly, nil
}

// MonitorAnomalies continuously monitors for anomalies in the device data.
func (ar *AnomalyRegistry) MonitorAnomalies(deviceID string) {
	monitoring_utils.Monitor(deviceID, func(data string) {
		signature := generateSignature(data, deviceID) // Mocked function to generate signature
		anomaly, err := ar.DetectAnomaly(deviceID, data, signature)
		if err != nil {
			log.Printf("Error detecting anomaly: %v", err)
		} else {
			log.Printf("Anomaly detected: %+v", anomaly)
		}
	})
}

// analyzeDataForAnomalies is a mock function to analyze data for anomalies.
func analyzeDataForAnomalies(data string) (string, string) {
	// Implement real data analysis here
	// For the sake of example, we will randomly return an anomaly type and severity
	return "Temperature Spike", "High"
}

// generateAnomalyID generates a unique ID for the anomaly.
func generateAnomalyID() string {
	return fmt.Sprintf("anomaly-%d", time.Now().UnixNano())
}

// generateSignature is a mocked function to generate a signature.
func generateSignature(data, deviceID string) string {
	// Mocked signature generation
	return "mocked-signature"
}
