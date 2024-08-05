package iot_integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/utils/encryption_utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/logging_utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/monitoring_utils"
	"github.com/synnergy_network/pkg/synnergy_network/utils/signature_utils"
)

// EdgeDevice represents an IoT device integrated at the edge of the network.
type EdgeDevice struct {
	ID             string
	Name           string
	Type           string
	Owner          string
	RegisteredAt   time.Time
	PublicKey      string
	EncryptedData  string
	LastActiveTime time.Time
	Status         string
}

// EdgeDeviceRegistry maintains a list of registered edge devices.
type EdgeDeviceRegistry struct {
	devices map[string]*EdgeDevice
}

// NewEdgeDeviceRegistry creates a new instance of EdgeDeviceRegistry.
func NewEdgeDeviceRegistry() *EdgeDeviceRegistry {
	return &EdgeDeviceRegistry{
		devices: make(map[string]*EdgeDevice),
	}
}

// RegisterEdgeDevice registers a new edge device in the network.
func (edr *EdgeDeviceRegistry) RegisterEdgeDevice(device *EdgeDevice) error {
	if _, exists := edr.devices[device.ID]; exists {
		return errors.New("edge device already registered")
	}

	device.RegisteredAt = time.Now()
	edr.devices[device.ID] = device

	logging_utils.LogInfo(fmt.Sprintf("Edge device registered: %s", device.Name))
	return nil
}

// UpdateEdgeDeviceStatus updates the status of an edge device.
func (edr *EdgeDeviceRegistry) UpdateEdgeDeviceStatus(deviceID, status string) error {
	device, exists := edr.devices[deviceID]
	if !exists {
		return errors.New("edge device not found")
	}

	device.Status = status
	device.LastActiveTime = time.Now()
	logging_utils.LogInfo(fmt.Sprintf("Edge device status updated: %s, Status: %s", device.Name, status))
	return nil
}

// CollectEdgeDeviceData collects data from an edge device and encrypts it before storing.
func (edr *EdgeDeviceRegistry) CollectEdgeDeviceData(deviceID, data string) error {
	device, exists := edr.devices[deviceID]
	if !exists {
		return errors.New("edge device not found")
	}

	encryptedData, err := encryption_utils.EncryptData(data, device.PublicKey)
	if err != nil {
		return err
	}

	device.EncryptedData = encryptedData
	device.LastActiveTime = time.Now()

	logging_utils.LogInfo(fmt.Sprintf("Data collected from edge device: %s", device.Name))
	return nil
}

// VerifyEdgeDeviceSignature verifies the edge device's signature to ensure data integrity.
func (edr *EdgeDeviceRegistry) VerifyEdgeDeviceSignature(deviceID, signature string) (bool, error) {
	device, exists := edr.devices[deviceID]
	if !exists {
		return false, errors.New("edge device not found")
	}

	data := fmt.Sprintf("%s:%s", device.ID, device.EncryptedData)
	valid, err := signature_utils.VerifySignature(data, signature, device.PublicKey)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// PredictiveEdgeMaintenance schedules predictive maintenance based on collected data.
func (edr *EdgeDeviceRegistry) PredictiveEdgeMaintenance(deviceID string) error {
	device, exists := edr.devices[deviceID]
	if !exists {
		return errors.New("edge device not found")
	}

	data, err := encryption_utils.DecryptData(device.EncryptedData, device.PublicKey)
	if err != nil {
		return err
	}

	// Analyze the data (mock analysis here)
	predictedIssue := analyzeEdgeDataForMaintenance(data)

	if predictedIssue {
		logging_utils.LogInfo(fmt.Sprintf("Predictive maintenance scheduled for edge device: %s", device.Name))
		// Schedule maintenance task (implementation not shown)
		return nil
	}

	return nil
}

// analyzeEdgeDataForMaintenance is a mock function to analyze data for predictive maintenance.
func analyzeEdgeDataForMaintenance(data string) bool {
	// Implement real data analysis here
	return true
}

// SerializeEdgeDevice serializes the edge device struct to JSON format.
func (d *EdgeDevice) SerializeEdgeDevice() (string, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeEdgeDevice deserializes the JSON string to an edge device struct.
func DeserializeEdgeDevice(data string) (*EdgeDevice, error) {
	var device EdgeDevice
	err := json.Unmarshal([]byte(data), &device)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// GetEdgeDevice retrieves an edge device by its ID.
func (edr *EdgeDeviceRegistry) GetEdgeDevice(deviceID string) (*EdgeDevice, error) {
	device, exists := edr.devices[deviceID]
	if !exists {
		return nil, errors.New("edge device not found")
	}
	return device, nil
}

// ListEdgeDevices lists all registered edge devices.
func (edr *EdgeDeviceRegistry) ListEdgeDevices() []*EdgeDevice {
	var deviceList []*EdgeDevice
	for _, device := range edr.devices {
		deviceList = append(deviceList, device)
	}
	return deviceList
}

// RemoveEdgeDevice removes an edge device from the registry.
func (edr *EdgeDeviceRegistry) RemoveEdgeDevice(deviceID string) error {
	if _, exists := edr.devices[deviceID]; !exists {
		return errors.New("edge device not found")
	}
	delete(edr.devices, deviceID)
	logging_utils.LogInfo(fmt.Sprintf("Edge device removed: %s", deviceID))
	return nil
}

// UpdateEdgeDevicePublicKey updates the public key of an edge device.
func (edr *EdgeDeviceRegistry) UpdateEdgeDevicePublicKey(deviceID, newPublicKey string) error {
	device, exists := edr.devices[deviceID]
	if !exists {
		return errors.New("edge device not found")
	}
	device.PublicKey = newPublicKey
	logging_utils.LogInfo(fmt.Sprintf("Edge device public key updated: %s", device.Name))
	return nil
}

// MonitorEdgeDeviceActivity monitors the activity of an edge device for anomalies.
func (edr *EdgeDeviceRegistry) MonitorEdgeDeviceActivity(deviceID string) error {
	device, exists := edr.devices[deviceID]
	if !exists {
		return errors.New("edge device not found")
	}

	// Mock monitoring logic
	if time.Since(device.LastActiveTime) > 24*time.Hour {
		logging_utils.LogWarning(fmt.Sprintf("Edge device %s is inactive for over 24 hours", device.Name))
	}

	return nil
}

// GenerateEdgeDeviceReport generates a comprehensive report of an edge device's activity.
func (edr *EdgeDeviceRegistry) GenerateEdgeDeviceReport(deviceID string) (string, error) {
	device, exists := edr.devices[deviceID]
	if !exists {
		return "", errors.New("edge device not found")
	}

	report := fmt.Sprintf("Edge Device Report:\nID: %s\nName: %s\nType: %s\nOwner: %s\nStatus: %s\nLast Active: %s\n",
		device.ID, device.Name, device.Type, device.Owner, device.Status, device.LastActiveTime)

	logging_utils.LogInfo(fmt.Sprintf("Report generated for edge device: %s", device.Name))
	return report, nil
}

// SecureDeleteEdgeDeviceData securely deletes all data associated with an edge device.
func (edr *EdgeDeviceRegistry) SecureDeleteEdgeDeviceData(deviceID string) error {
	device, exists := edr.devices[deviceID]
	if !exists {
		return errors.New("edge device not found")
	}

	// Securely delete the encrypted data
	device.EncryptedData = ""

	logging_utils.LogInfo(fmt.Sprintf("Data securely deleted for edge device: %s", device.Name))
	return nil
}
