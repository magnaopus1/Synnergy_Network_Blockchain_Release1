package fault_detection

import (
	"encoding/json"
	"log"
	"math"
	"os"
	"time"

	"pkg/synnergy_network/core/utils"
	"pkg/synnergy_network/core/operations/blockchain_maintenance/maintenance/automated_alerting_systems"
	"pkg/synnergy_network/core/operations/blockchain_maintenance/maintenance/dynamic_parameter_adjustment"
	"pkg/synnergy_network/core/operations/blockchain_maintenance/maintenance/security_compliance"
	"pkg/synnergy_network/core/operations/blockchain_maintenance/maintenance/iot_integration"
)

// Anomaly represents a detected anomaly in the network.
type Anomaly struct {
	Timestamp   time.Time `json:"timestamp"`
	NodeID      string    `json:"node_id"`
	Metric      string    `json:"metric"`
	Value       float64   `json:"value"`
	Description string    `json:"description"`
}

// AnomalyDetection is responsible for detecting anomalies in the network.
type AnomalyDetection struct {
	alertSystem   automated_alerting_systems.AlertSystem
	encryption    utils.EncryptionUtils
	parameterAdj  dynamic_parameter_adjustment.ParameterTuning
	security      security_compliance.SecurityCompliance
	iotIntegration iot_integration.IoTIntegration
}

// NewAnomalyDetection creates a new instance of AnomalyDetection.
func NewAnomalyDetection() *AnomalyDetection {
	return &AnomalyDetection{
		alertSystem:   automated_alerting_systems.NewAlertSystem(),
		encryption:    utils.NewEncryptionUtils(),
		parameterAdj:  dynamic_parameter_adjustment.NewParameterTuning(),
		security:      security_compliance.NewSecurityCompliance(),
		iotIntegration: iot_integration.NewIoTIntegration(),
	}
}

// Monitor continuously monitors the network for anomalies.
func (ad *AnomalyDetection) Monitor() {
	for {
		data, err := ad.iotIntegration.CollectRealTimeData()
		if err != nil {
			log.Printf("Error collecting IoT data: %v", err)
			continue
		}

		for nodeID, metrics := range data {
			for metric, value := range metrics {
				if ad.isAnomalous(nodeID, metric, value) {
					anomaly := Anomaly{
						Timestamp:   time.Now(),
						NodeID:      nodeID,
						Metric:      metric,
						Value:       value,
						Description: "Detected anomaly in network metric",
					}
					ad.handleAnomaly(anomaly)
				}
			}
		}
		time.Sleep(1 * time.Minute)
	}
}

// isAnomalous checks if a given metric value is anomalous.
func (ad *AnomalyDetection) isAnomalous(nodeID, metric string, value float64) bool {
	thresholds, err := ad.parameterAdj.GetThresholds()
	if err != nil {
		log.Printf("Error getting thresholds: %v", err)
		return false
	}

	if threshold, ok := thresholds[metric]; ok {
		return math.Abs(value) > threshold
	}

	return false
}

// handleAnomaly processes a detected anomaly.
func (ad *AnomalyDetection) handleAnomaly(anomaly Anomaly) {
	log.Printf("Anomaly detected: %+v", anomaly)
	ad.alertSystem.TriggerAlert(anomaly.NodeID, anomaly.Metric, anomaly.Description)
	ad.logAnomaly(anomaly)
	ad.security.InitiateResponse(anomaly.NodeID)
}

// logAnomaly logs the anomaly details.
func (ad *AnomalyDetection) logAnomaly(anomaly Anomaly) {
	file, err := os.OpenFile("anomalies.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening anomaly log file: %v", err)
		return
	}
	defer file.Close()

	anomalyJSON, err := json.Marshal(anomaly)
	if err != nil {
		log.Printf("Error marshaling anomaly data: %v", err)
		return
	}

	if _, err := file.Write(anomalyJSON); err != nil {
		log.Printf("Error writing anomaly to log file: %v", err)
	}
}

// EncryptData encrypts data before logging it for security.
func (ad *AnomalyDetection) EncryptData(data []byte) ([]byte, error) {
	return ad.encryption.Encrypt(data)
}

// DecryptData decrypts data for analysis.
func (ad *AnomalyDetection) DecryptData(data []byte) ([]byte, error) {
	return ad.encryption.Decrypt(data)
}
