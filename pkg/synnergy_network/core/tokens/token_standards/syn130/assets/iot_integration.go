package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/utils"
)

// IoTIntegrationManager handles the integration of IoT devices with assets
type IoTIntegrationManager struct {
	AssetIoTDevices map[string][]IoTDevice
	Mutex           sync.Mutex
}

// IoTDevice represents a single IoT device linked to an asset
type IoTDevice struct {
	DeviceID   string
	DeviceType string
	LastUpdate time.Time
	Data       map[string]float64
	Status     string
}

// NewIoTIntegrationManager creates a new instance of IoTIntegrationManager
func NewIoTIntegrationManager() *IoTIntegrationManager {
	return &IoTIntegrationManager{
		AssetIoTDevices: make(map[string][]IoTDevice),
	}
}

// AddIoTDevice adds a new IoT device to an asset
func (iot *IoTIntegrationManager) AddIoTDevice(assetID string, device IoTDevice) error {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	iot.AssetIoTDevices[assetID] = append(iot.AssetIoTDevices[assetID], device)
	return nil
}

// UpdateIoTDeviceData updates the data for a specific IoT device
func (iot *IoTIntegrationManager) UpdateIoTDeviceData(assetID string, deviceID string, data map[string]float64) error {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	devices, exists := iot.AssetIoTDevices[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	for i, device := range devices {
		if device.DeviceID == deviceID {
			device.Data = data
			device.LastUpdate = time.Now()
			iot.AssetIoTDevices[assetID][i] = device
			return nil
		}
	}
	return errors.New("device not found")
}

// GetIoTDeviceData retrieves the data for a specific IoT device
func (iot *IoTIntegrationManager) GetIoTDeviceData(assetID string, deviceID string) (IoTDevice, error) {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	devices, exists := iot.AssetIoTDevices[assetID]
	if !exists {
		return IoTDevice{}, errors.New("asset not found")
	}

	for _, device := range devices {
		if device.DeviceID == deviceID {
			return device, nil
		}
	}
	return IoTDevice{}, errors.New("device not found")
}

// MonitorAssets monitors the assets for real-time data updates and triggers necessary actions
func (iot *IoTIntegrationManager) MonitorAssets(assetID string) error {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	devices, exists := iot.AssetIoTDevices[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	for _, device := range devices {
		// Example logic to handle device data and trigger actions
		for key, value := range device.Data {
			if value > 100 { // Example threshold condition
				iot.TriggerAlert(assetID, device.DeviceID, key, value)
			}
		}
	}
	return nil
}

// TriggerAlert triggers an alert based on IoT device data
func (iot *IoTIntegrationManager) TriggerAlert(assetID, deviceID, dataKey string, dataValue float64) {
	// Implement alert logic, such as sending notifications or recording the event
	alertMessage := map[string]interface{}{
		"assetID":   assetID,
		"deviceID":  deviceID,
		"dataKey":   dataKey,
		"dataValue": dataValue,
		"timestamp": time.Now(),
	}

	alertJSON, _ := json.Marshal(alertMessage)
	storage.Save("/alerts/"+assetID+"_"+deviceID+"_"+dataKey+".json", alertJSON)
}

// SaveIoTData saves the IoT device data to persistent storage
func (iot *IoTIntegrationManager) SaveIoTData(storagePath string) error {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	data, err := json.Marshal(iot.AssetIoTDevices)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadIoTData loads the IoT device data from persistent storage
func (iot *IoTIntegrationManager) LoadIoTData(storagePath string) error {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &iot.AssetIoTDevices)
	if err != nil {
		return err
	}
	return nil
}

// GenerateIoTReport generates a report for all IoT devices linked to a specific asset
func (iot *IoTIntegrationManager) GenerateIoTReport(assetID string) (string, error) {
	devices, err := iot.GetAssetIoTDevices(assetID)
	if err != nil {
		return "", err
	}

	report := struct {
		AssetID  string
		Devices  []IoTDevice
	}{
		AssetID: assetID,
		Devices: devices,
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", err
	}

	return string(reportJSON), nil
}

// GetAssetIoTDevices retrieves all IoT devices linked to a specific asset
func (iot *IoTIntegrationManager) GetAssetIoTDevices(assetID string) ([]IoTDevice, error) {
	iot.Mutex.Lock()
	defer iot.Mutex.Unlock()

	devices, exists := iot.AssetIoTDevices[assetID]
	if !exists {
		return nil, errors.New("asset not found")
	}
	return devices, nil
}
