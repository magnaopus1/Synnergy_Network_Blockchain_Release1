package extended_features

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/carbon_credit_system"
)

// IoTDevice represents an IoT device that records emission data.
type IoTDevice struct {
	ID        string
	Owner     string
	Location  string
	Active    bool
	DataQueue chan EmissionData
}

// EmissionData represents emission data recorded by an IoT device.
type EmissionData struct {
	DeviceID      string
	Timestamp     time.Time
	CO2Emission   float64
	TokenID       string
	Verified      bool
}

// NewIoTDevice creates a new IoT device.
func NewIoTDevice(owner, location string) (*IoTDevice, error) {
	id, err := generateUniqueID()
	if err != nil {
		return nil, err
	}
	device := &IoTDevice{
		ID:        id,
		Owner:     owner,
		Location:  location,
		Active:    true,
		DataQueue: make(chan EmissionData, 100),
	}
	return device, nil
}

// generateUniqueID generates a unique identifier.
func generateUniqueID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CarbonCreditPlatform represents the platform for managing carbon credits.
type CarbonCreditPlatform struct {
	tokens          map[string]*carbon_credit_system.CarbonCreditToken
	devices         map[string]*IoTDevice
	dataFeedChannel chan EmissionData
}

// NewCarbonCreditPlatform creates a new carbon credit platform.
func NewCarbonCreditPlatform() *CarbonCreditPlatform {
	return &CarbonCreditPlatform{
		tokens:          make(map[string]*carbon_credit_system.CarbonCreditToken),
		devices:         make(map[string]*IoTDevice),
		dataFeedChannel: make(chan EmissionData),
	}
}

// AddDevice adds a new IoT device to the platform.
func (platform *CarbonCreditPlatform) AddDevice(device *IoTDevice) {
	platform.devices[device.ID] = device
}

// AddToken adds a new carbon credit token to the platform.
func (platform *CarbonCreditPlatform) AddToken(token *carbon_credit_system.CarbonCreditToken) {
	platform.tokens[token.ID] = token
}

// RecordEmissionData records emission data from IoT devices.
func (platform *CarbonCreditPlatform) RecordEmissionData(data EmissionData) {
	platform.dataFeedChannel <- data
}

// MonitorIoTDevices monitors IoT devices and processes emission data.
func (platform *CarbonCreditPlatform) MonitorIoTDevices() {
	for data := range platform.dataFeedChannel {
		token, exists := platform.tokens[data.TokenID]
		if exists && !token.IsRetired {
			token.Amount -= data.CO2Emission
			if token.Amount <= 0 {
				token.IsRetired = true
			}
			data.Verified = true
			fmt.Printf("Emission data processed: DeviceID: %s, CO2Emission: %f, Verified: %v\n", data.DeviceID, data.CO2Emission, data.Verified)
		} else {
			data.Verified = false
			fmt.Printf("Emission data rejected: DeviceID: %s, CO2Emission: %f, Verified: %v\n", data.DeviceID, data.CO2Emission, data.Verified)
		}
	}
}

func main() {
	platform := NewCarbonCreditPlatform()

	// Example usage
	device, _ := NewIoTDevice("Alice", "Location1")
	platform.AddDevice(device)

	token, _ := carbon_credit_system.NewCarbonCreditToken("Alice", 100, time.Now().Add(24*time.Hour))
	platform.AddToken(token)

	data := EmissionData{
		DeviceID:    device.ID,
		Timestamp:   time.Now(),
		CO2Emission: 10,
		TokenID:     token.ID,
	}

	go platform.MonitorIoTDevices()

	platform.RecordEmissionData(data)
	time.Sleep(1 * time.Second) // Give some time for the data to be processed
}
