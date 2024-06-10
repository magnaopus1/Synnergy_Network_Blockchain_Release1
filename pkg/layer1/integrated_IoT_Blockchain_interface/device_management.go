package iot_interface

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"

	"golang.org/x/crypto/scrypt"
)

// Device represents a single IoT device within the blockchain network.
type Device struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	SecurityKey string `json:"securityKey"`
	Status      string `json:"status"`
}

// DeviceManager handles the registration, updating, and querying of IoT devices.
type DeviceManager struct {
	devices map[string]*Device
}

// NewDeviceManager initializes a new DeviceManager.
func NewDeviceManager() *DeviceManager {
	return &DeviceManager{
		devices: make(map[string]*Device),
	}
}

// RegisterDevice registers a new IoT device in the system.
func (dm *DeviceManager) RegisterDevice(id, description string) error {
	if _, exists := dm.devices[id]; exists {
		return errors.New("device already registered")
	}

	securityKey, err := generateSecurityKey()
	if err != nil {
		return err
	}

	dm.devices[id] = &Device{
		ID:          id,
		Description: description,
		SecurityKey: securityKey,
		Status:      "active",
	}
	log.Printf("Device registered: %s", id)
	return nil
}

// UpdateDeviceStatus updates the status of an existing IoT device.
func (dm *DeviceManager) UpdateDeviceStatus(id, status string) error {
	device, exists := dm.devices[id]
	if !exists {
		return errors.New("device not found")
	}

	device.Status = status
	log.Printf("Device status updated: %s - %s", id, status)
	return nil
}

// GetDevice retrieves details about a specific IoT device.
func (dm *DeviceManager) GetDevice(id string) (*Device, error) {
	device, exists := dm.devices[id]
	if !exists {
		return nil, errors.New("device not found")
	}
	return device, nil
}

// generateSecurityKey creates a unique security key for each IoT device.
func generateSecurityKey() (string, error) {
	b := make([]byte, 16) // 128 bits are usually enough, but you may want to use 256
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	key, err := scrypt.Key(b, b, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// MarshalDeviceList marshals the list of devices into a JSON format.
func (dm *DeviceManager) MarshalDeviceList() (string, error) {
	data, err := json.Marshal(dm.devices)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Example usage and function testing should be implemented to validate the features.
