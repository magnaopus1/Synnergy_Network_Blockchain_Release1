package iot_integration

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network/utils"
	"github.com/synnergy_network/security"
	"github.com/synnergy_network/core/operations/blockchain_maintenance/diagnostic_tools"
)

// Device represents an IoT device in the network.
type Device struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	LastUpdated time.Time `json:"last_updated"`
	Data        map[string]interface{} `json:"data"`
}

// DeviceManager manages the devices in the IoT network.
type DeviceManager struct {
	devices map[string]*Device
	mu      sync.RWMutex
}

// NewDeviceManager creates a new DeviceManager.
func NewDeviceManager() *DeviceManager {
	return &DeviceManager{
		devices: make(map[string]*Device),
	}
}

// AddDevice adds a new device to the manager.
func (dm *DeviceManager) AddDevice(device *Device) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.devices[device.ID] = device
}

// RemoveDevice removes a device from the manager.
func (dm *DeviceManager) RemoveDevice(deviceID string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	delete(dm.devices, deviceID)
}

// GetDevice retrieves a device by its ID.
func (dm *DeviceManager) GetDevice(deviceID string) (*Device, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	device, exists := dm.devices[deviceID]
	return device, exists
}

// UpdateDeviceStatus updates the status of a device.
func (dm *DeviceManager) UpdateDeviceStatus(deviceID string, status string) bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if device, exists := dm.devices[deviceID]; exists {
		device.Status = status
		device.LastUpdated = time.Now()
		return true
	}
	return false
}

// CollectData collects data from a device.
func (dm *DeviceManager) CollectData(deviceID string, data map[string]interface{}) bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if device, exists := dm.devices[deviceID]; exists {
		for key, value := range data {
			device.Data[key] = value
		}
		device.LastUpdated = time.Now()
		return true
	}
	return false
}

// EncryptData encrypts the data using the appropriate encryption method.
func EncryptData(data []byte) ([]byte, error) {
	return security.EncryptAES(data)
}

// DecryptData decrypts the data using the appropriate decryption method.
func DecryptData(data []byte) ([]byte, error) {
	return security.DecryptAES(data)
}

// CollectDataHandler handles data collection requests from IoT devices.
func (dm *DeviceManager) CollectDataHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		DeviceID string                 `json:"device_id"`
		Data     map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if dm.CollectData(requestData.DeviceID, requestData.Data) {
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Device not found", http.StatusNotFound)
	}
}

// DeviceManagementHandler handles the registration and removal of devices.
func (dm *DeviceManager) DeviceManagementHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Action   string  `json:"action"`
		DeviceID string  `json:"device_id"`
		Device   *Device `json:"device,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	switch requestData.Action {
	case "add":
		if requestData.Device != nil {
			dm.AddDevice(requestData.Device)
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "Device data missing", http.StatusBadRequest)
		}
	case "remove":
		dm.RemoveDevice(requestData.DeviceID)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
	}
}

// MonitorDevices continuously monitors the devices and performs predictive maintenance.
func (dm *DeviceManager) MonitorDevices() {
	for {
		time.Sleep(10 * time.Second) // Adjust the interval as needed.
		dm.mu.RLock()
		for _, device := range dm.devices {
			// Perform predictive maintenance checks
			diagnostic_tools.PerformPredictiveMaintenance(device)
		}
		dm.mu.RUnlock()
	}
}

// StartServer starts the HTTP server for managing and collecting data from IoT devices.
func StartServer(dm *DeviceManager) {
	http.HandleFunc("/collect", dm.CollectDataHandler)
	http.HandleFunc("/manage", dm.DeviceManagementHandler)

	log.Fatal(http.ListenAndServe(":8080", nil)) // Port can be configured as needed.
}


