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

// Device represents an IoT device integrated into the blockchain network.
type Device struct {
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

// DeviceRegistry maintains a list of registered devices.
type DeviceRegistry struct {
	devices map[string]*Device
}

// NewDeviceRegistry creates a new instance of DeviceRegistry.
func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{
		devices: make(map[string]*Device),
	}
}

// RegisterDevice registers a new device in the blockchain network.
func (dr *DeviceRegistry) RegisterDevice(device *Device) error {
	if _, exists := dr.devices[device.ID]; exists {
		return errors.New("device already registered")
	}

	device.RegisteredAt = time.Now()
	dr.devices[device.ID] = device

	logging_utils.LogInfo(fmt.Sprintf("Device registered: %s", device.Name))
	return nil
}

// UpdateDeviceStatus updates the status of a device.
func (dr *DeviceRegistry) UpdateDeviceStatus(deviceID, status string) error {
	device, exists := dr.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	device.Status = status
	device.LastActiveTime = time.Now()
	logging_utils.LogInfo(fmt.Sprintf("Device status updated: %s, Status: %s", device.Name, status))
	return nil
}

// CollectData collects data from a device and encrypts it before storing.
func (dr *DeviceRegistry) CollectData(deviceID, data string) error {
	device, exists := dr.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	encryptedData, err := encryption_utils.EncryptData(data, device.PublicKey)
	if err != nil {
		return err
	}

	device.EncryptedData = encryptedData
	device.LastActiveTime = time.Now()

	logging_utils.LogInfo(fmt.Sprintf("Data collected from device: %s", device.Name))
	return nil
}

// VerifyDeviceSignature verifies the device's signature to ensure data integrity.
func (dr *DeviceRegistry) VerifyDeviceSignature(deviceID, signature string) (bool, error) {
	device, exists := dr.devices[deviceID]
	if !exists {
		return false, errors.New("device not found")
	}

	data := fmt.Sprintf("%s:%s", device.ID, device.EncryptedData)
	valid, err := signature_utils.VerifySignature(data, signature, device.PublicKey)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// PredictiveMaintenance schedules predictive maintenance based on collected data.
func (dr *DeviceRegistry) PredictiveMaintenance(deviceID string) error {
	device, exists := dr.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	data, err := encryption_utils.DecryptData(device.EncryptedData, device.PublicKey)
	if err != nil {
		return err
	}

	// Analyze the data (mock analysis here)
	predictedIssue := analyzeDataForMaintenance(data)

	if predictedIssue {
		logging_utils.LogInfo(fmt.Sprintf("Predictive maintenance scheduled for device: %s", device.Name))
		// Schedule maintenance task (implementation not shown)
		return nil
	}

	return nil
}

// analyzeDataForMaintenance is a mock function to analyze data for predictive maintenance.
func analyzeDataForMaintenance(data string) bool {
	// Implement real data analysis here
	return true
}

// SerializeDevice serializes the device struct to JSON format.
func (d *Device) SerializeDevice() (string, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeDevice deserializes the JSON string to a device struct.
func DeserializeDevice(data string) (*Device, error) {
	var device Device
	err := json.Unmarshal([]byte(data), &device)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// GetDevice retrieves a device by its ID.
func (dr *DeviceRegistry) GetDevice(deviceID string) (*Device, error) {
	device, exists := dr.devices[deviceID]
	if !exists {
		return nil, errors.New("device not found")
	}
	return device, nil
}

// ListDevices lists all registered devices.
func (dr *DeviceRegistry) ListDevices() []*Device {
	var deviceList []*Device
	for _, device := range dr.devices {
		deviceList = append(deviceList, device)
	}
	return deviceList
}

// RemoveDevice removes a device from the registry.
func (dr *DeviceRegistry) RemoveDevice(deviceID string) error {
	if _, exists := dr.devices[deviceID]; !exists {
		return errors.New("device not found")
	}
	delete(dr.devices, deviceID)
	logging_utils.LogInfo(fmt.Sprintf("Device removed: %s", deviceID))
	return nil
}

// UpdateDevicePublicKey updates the public key of a device.
func (dr *DeviceRegistry) UpdateDevicePublicKey(deviceID, newPublicKey string) error {
	device, exists := dr.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}
	device.PublicKey = newPublicKey
	logging_utils.LogInfo(fmt.Sprintf("Device public key updated: %s", device.Name))
	return nil
}

// MonitorDeviceActivity monitors the activity of a device for anomalies.
func (dr *DeviceRegistry) MonitorDeviceActivity(deviceID string) error {
	device, exists := dr.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	// Mock monitoring logic
	if time.Since(device.LastActiveTime) > 24*time.Hour {
		logging_utils.LogWarning(fmt.Sprintf("Device %s is inactive for over 24 hours", device.Name))
	}

	return nil
}

// GenerateDeviceReport generates a comprehensive report of a device's activity.
func (dr *DeviceRegistry) GenerateDeviceReport(deviceID string) (string, error) {
	device, exists := dr.devices[deviceID]
	if !exists {
		return "", errors.New("device not found")
	}

	report := fmt.Sprintf("Device Report:\nID: %s\nName: %s\nType: %s\nOwner: %s\nStatus: %s\nLast Active: %s\n",
		device.ID, device.Name, device.Type, device.Owner, device.Status, device.LastActiveTime)

	logging_utils.LogInfo(fmt.Sprintf("Report generated for device: %s", device.Name))
	return report, nil
}

// SecureDeleteDeviceData securely deletes all data associated with a device.
func (dr *DeviceRegistry) SecureDeleteDeviceData(deviceID string) error {
	device, exists := dr.devices[deviceID]
	if !exists {
		return errors.New("device not found")
	}

	// Securely delete the encrypted data
	device.EncryptedData = ""

	logging_utils.LogInfo(fmt.Sprintf("Data securely deleted for device: %s", device.Name))
	return nil
}

