package dynamic_targets

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// SustainabilityMetric represents a sustainability metric to be tracked.
type SustainabilityMetric struct {
	MetricID          string  `json:"metric_id"`
	Name              string  `json:"name"`
	Unit              string  `json:"unit"`
	Value             float64 `json:"value"`
	LastUpdated       string  `json:"last_updated"`
	Target            float64 `json:"target"`
	PerformanceStatus string  `json:"performance_status"`
}

// SustainabilityReport represents a report containing various sustainability metrics.
type SustainabilityReport struct {
	ReportID    string                `json:"report_id"`
	GeneratedAt string                `json:"generated_at"`
	Metrics     []SustainabilityMetric `json:"metrics"`
}

// NewSustainabilityMetric creates a new sustainability metric.
func NewSustainabilityMetric(metricID, name, unit string, value, target float64) *SustainabilityMetric {
	return &SustainabilityMetric{
		MetricID:          metricID,
		Name:              name,
		Unit:              unit,
		Value:             value,
		LastUpdated:       time.Now().Format(time.RFC3339),
		Target:            target,
		PerformanceStatus: evaluatePerformance(value, target),
	}
}

// evaluatePerformance evaluates the performance status of a metric based on its target.
func evaluatePerformance(value, target float64) string {
	if value < target {
		return "Below Target"
	} else if value == target {
		return "On Target"
	} else {
		return "Above Target"
	}
}

// UpdateMetric updates the value of an existing sustainability metric and re-evaluates its performance.
func (metric *SustainabilityMetric) UpdateMetric(newValue float64) {
	metric.Value = newValue
	metric.LastUpdated = time.Now().Format(time.RFC3339)
	metric.PerformanceStatus = evaluatePerformance(newValue, metric.Target)
}

// SaveMetric saves the sustainability metric to the blockchain.
func (metric *SustainabilityMetric) SaveMetric() error {
	metricJSON, err := json.Marshal(metric)
	if err != nil {
		return err
	}
	return blockchain.PutState(metric.MetricID, metricJSON)
}

// GetMetric retrieves a sustainability metric from the blockchain.
func GetMetric(metricID string) (*SustainabilityMetric, error) {
	metricJSON, err := blockchain.GetState(metricID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if metricJSON == nil {
		return nil, fmt.Errorf("the metric %s does not exist", metricID)
	}

	var metric SustainabilityMetric
	err = json.Unmarshal(metricJSON, &metric)
	if err != nil {
		return nil, err
	}

	return &metric, nil
}

// GenerateSustainabilityReport generates a report of current sustainability metrics.
func GenerateSustainabilityReport(metrics []SustainabilityMetric) (*SustainabilityReport, error) {
	reportID := fmt.Sprintf("report-%d", time.Now().Unix())
	report := &SustainabilityReport{
		ReportID:    reportID,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Metrics:     metrics,
	}
	return report, nil
}

// SaveReport saves the sustainability report to the blockchain.
func (report *SustainabilityReport) SaveReport() error {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return blockchain.PutState(report.ReportID, reportJSON)
}

// GetReport retrieves a sustainability report from the blockchain.
func GetReport(reportID string) (*SustainabilityReport, error) {
	reportJSON, err := blockchain.GetState(reportID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if reportJSON == nil {
		return nil, fmt.Errorf("the report %s does not exist", reportID)
	}

	var report SustainabilityReport
	err = json.Unmarshal(reportJSON, &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}

// ListAllMetrics lists all sustainability metrics.
func ListAllMetrics() ([]SustainabilityMetric, error) {
	// Placeholder for a method to list all sustainability metrics.
	// This would typically involve querying the blockchain ledger for all metric records.
	// For now, we return an empty list.
	return []SustainabilityMetric{}, nil
}

// ListAllReports lists all sustainability reports.
func ListAllReports() ([]SustainabilityReport, error) {
	// Placeholder for a method to list all sustainability reports.
	// This would typically involve querying the blockchain ledger for all report records.
	// For now, we return an empty list.
	return []SustainabilityReport{}, nil
}

// AdjustTarget adjusts the target value of a sustainability metric.
func (metric *SustainabilityMetric) AdjustTarget(newTarget float64) {
	metric.Target = newTarget
	metric.LastUpdated = time.Now().Format(time.RFC3339)
	metric.PerformanceStatus = evaluatePerformance(metric.Value, newTarget)
}

// HandleMetricUpdate handles the update request for a sustainability metric.
func HandleMetricUpdate(metricID string, newValue, newTarget float64) error {
	metric, err := GetMetric(metricID)
	if err != nil {
		return err
	}

	metric.UpdateMetric(newValue)
	metric.AdjustTarget(newTarget)
	return metric.SaveMetric()
}

// MetricUpdateRequest represents a request to update a sustainability metric.
type MetricUpdateRequest struct {
	MetricID string  `json:"metric_id"`
	NewValue float64 `json:"new_value"`
	NewTarget float64 `json:"new_target"`
}

// HandleMetricUpdateRequest handles the update request for a sustainability metric.
func HandleMetricUpdateRequest(request MetricUpdateRequest) error {
	return HandleMetricUpdate(request.MetricID, request.NewValue, request.NewTarget)
}

// GenerateMetricUpdateRequest generates an update request for a sustainability metric.
func GenerateMetricUpdateRequest(metricID string, newValue, newTarget float64) MetricUpdateRequest {
	return MetricUpdateRequest{
		MetricID:  metricID,
		NewValue:  newValue,
		NewTarget: newTarget,
	}
}

// EncryptData encrypts data using AES.
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using AES.
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("invalid data")
	}

	salt, ciphertext := data[:32], data[32:]

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
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

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
