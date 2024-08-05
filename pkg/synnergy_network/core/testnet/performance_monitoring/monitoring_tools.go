package performance_monitoring

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/synnergy_network/core/encryption"
	"github.com/synnergy_network/core/utils"
)

// MonitoringTools is the main struct for performance monitoring
type MonitoringTools struct {
	NodeHealth      NodeHealthMonitor
	ResourceUsage   ResourceUsageMonitor
	TransactionData TransactionMonitor
}

// NodeHealthMonitor struct for monitoring the health of nodes
type NodeHealthMonitor struct {
	Nodes []Node
}

// Node represents a single node in the network
type Node struct {
	ID             string
	LastHeartbeat  time.Time
	Status         string
	CPUUsage       float64
	MemoryUsage    float64
	DiskUsage      float64
	NetworkLatency float64
}

// ResourceUsageMonitor struct for monitoring resource usage
type ResourceUsageMonitor struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
}

// TransactionMonitor struct for monitoring transaction data
type TransactionMonitor struct {
	Throughput   int
	ConfirmationTimes []time.Duration
}

// LoadConfig loads the monitoring configuration from a file
func (mt *MonitoringTools) LoadConfig(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open config file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(mt); err != nil {
		return fmt.Errorf("could not decode config JSON: %w", err)
	}
	return nil
}

// SaveConfig saves the monitoring configuration to a file
func (mt *MonitoringTools) SaveConfig(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(mt); err != nil {
		return fmt.Errorf("could not encode config JSON: %w", err)
	}
	return nil
}

// UpdateNodeHealth updates the health status of a node
func (nhm *NodeHealthMonitor) UpdateNodeHealth(nodeID string, status string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	for i, node := range nhm.Nodes {
		if node.ID == nodeID {
			nhm.Nodes[i].LastHeartbeat = time.Now()
			nhm.Nodes[i].Status = status
			nhm.Nodes[i].CPUUsage = cpuUsage
			nhm.Nodes[i].MemoryUsage = memoryUsage
			nhm.Nodes[i].DiskUsage = diskUsage
			nhm.Nodes[i].NetworkLatency = latency
			return nil
		}
	}
	return fmt.Errorf("node with ID %s not found", nodeID)
}

// MonitorResourceUsage monitors the resource usage of the network
func (rum *ResourceUsageMonitor) MonitorResourceUsage() {
	rum.CPUUsage = utils.GetCPUUsage()
	rum.MemoryUsage = utils.GetMemoryUsage()
	rum.DiskUsage = utils.GetDiskUsage()
}

// TrackTransaction monitors transaction throughput and confirmation times
func (tm *TransactionMonitor) TrackTransaction(throughput int, confirmationTime time.Duration) {
	tm.Throughput += throughput
	tm.ConfirmationTimes = append(tm.ConfirmationTimes, confirmationTime)
}

// GenerateReport generates a performance monitoring report
func (mt *MonitoringTools) GenerateReport() (string, error) {
	report := struct {
		NodeHealth      []Node
		ResourceUsage   ResourceUsageMonitor
		TransactionData TransactionMonitor
	}{
		NodeHealth:      mt.NodeHealth.Nodes,
		ResourceUsage:   mt.ResourceUsage,
		TransactionData: mt.TransactionData,
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("could not generate report JSON: %w", err)
	}

	return string(reportJSON), nil
}

// EncryptReport encrypts the monitoring report using the specified encryption method
func (mt *MonitoringTools) EncryptReport(report string, encryptionMethod string, key []byte) (string, error) {
	var encryptedReport []byte
	var err error

	switch encryptionMethod {
	case "scrypt":
		encryptedReport, err = encryption.EncryptScrypt([]byte(report), key)
	case "aes":
		encryptedReport, err = encryption.EncryptAES([]byte(report), key)
	case "argon2":
		encryptedReport, err = encryption.EncryptArgon2([]byte(report), key)
	default:
		return "", fmt.Errorf("unsupported encryption method: %s", encryptionMethod)
	}

	if err != nil {
		return "", fmt.Errorf("could not encrypt report: %w", err)
	}

	return string(encryptedReport), nil
}

// DecryptReport decrypts the monitoring report using the specified decryption method
func (mt *MonitoringTools) DecryptReport(encryptedReport string, decryptionMethod string, key []byte) (string, error) {
	var decryptedReport []byte
	var err error

	switch decryptionMethod {
	case "scrypt":
		decryptedReport, err = encryption.DecryptScrypt([]byte(encryptedReport), key)
	case "aes":
		decryptedReport, err = encryption.DecryptAES([]byte(encryptedReport), key)
	case "argon2":
		decryptedReport, err = encryption.DecryptArgon2([]byte(encryptedReport), key)
	default:
		return "", fmt.Errorf("unsupported decryption method: %s", decryptionMethod)
	}

	if err != nil {
		return "", fmt.Errorf("could not decrypt report: %w", err)
	}

	return string(decryptedReport), nil
}

// NewMonitoringTools initializes a new MonitoringTools instance
func NewMonitoringTools() *MonitoringTools {
	return &MonitoringTools{
		NodeHealth: NodeHealthMonitor{
			Nodes: make([]Node, 0),
		},
		ResourceUsage: ResourceUsageMonitor{},
		TransactionData: TransactionMonitor{
			Throughput:        0,
			ConfirmationTimes: make([]time.Duration, 0),
		},
	}
}
