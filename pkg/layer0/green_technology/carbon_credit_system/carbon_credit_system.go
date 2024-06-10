package verification_tracking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/carbon_credit_system"
)

// EmissionData represents emission data to be tracked.
type EmissionData struct {
	DeviceID    string
	Timestamp   time.Time
	CO2Emission float64
	Hash        string
}

// EmissionTracker handles the tracking and verification of emission data.
type EmissionTracker struct {
	emissionData map[string]EmissionData
	tokens       map[string]*carbon_credit_system.CarbonCreditToken
}

// NewEmissionTracker creates a new instance of EmissionTracker.
func NewEmissionTracker() *EmissionTracker {
	return &EmissionTracker{
		emissionData: make(map[string]EmissionData),
		tokens:       make(map[string]*carbon_credit_system.CarbonCreditToken),
	}
}

// RecordEmissionData records new emission data and generates a hash for it.
func (et *EmissionTracker) RecordEmissionData(deviceID string, emission float64) (EmissionData, error) {
	timestamp := time.Now()
	data := EmissionData{
		DeviceID:    deviceID,
		Timestamp:   timestamp,
		CO2Emission: emission,
		Hash:        generateHash(deviceID, timestamp, emission),
	}
	et.emissionData[deviceID] = data
	return data, nil
}

// VerifyEmissionData verifies the integrity of emission data using its hash.
func (et *EmissionTracker) VerifyEmissionData(deviceID string, timestamp time.Time, emission float64, hash string) bool {
	expectedHash := generateHash(deviceID, timestamp, emission)
	return expectedHash == hash
}

// AddToken adds a new carbon credit token to the tracker.
func (et *EmissionTracker) AddToken(token *carbon_credit_system.CarbonCreditToken) {
	et.tokens[token.ID] = token
}

// ConsumeToken consumes a specified amount from a carbon credit token.
func (et *EmissionTracker) ConsumeToken(tokenID string, amount float64) error {
	token, exists := et.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	if token.IsRetired {
		return errors.New("token is retired")
	}
	if token.Amount < amount {
		return errors.New("insufficient token amount")
	}
	token.Amount -= amount
	if token.Amount <= 0 {
		token.IsRetired = true
	}
	return nil
}

// generateHash generates a SHA-256 hash for the emission data.
func generateHash(deviceID string, timestamp time.Time, emission float64) string {
	record := fmt.Sprintf("%s:%s:%f", deviceID, timestamp.String(), emission)
	hash := sha256.New()
	hash.Write([]byte(record))
	return hex.EncodeToString(hash.Sum(nil))
}

func main() {
	// Example usage
	tracker := NewEmissionTracker()

	// Record new emission data
	emissionData, err := tracker.RecordEmissionData("Device1", 10.5)
	if err != nil {
		fmt.Println("Error recording emission data:", err)
		return
	}
	fmt.Printf("Recorded emission data: %+v\n", emissionData)

	// Verify emission data
	isValid := tracker.VerifyEmissionData(emissionData.DeviceID, emissionData.Timestamp, emissionData.CO2Emission, emissionData.Hash)
	if !isValid {
		fmt.Println("Emission data verification failed")
	} else {
		fmt.Println("Emission data verification succeeded")
	}

	// Add a new token
	token, _ := carbon_credit_system.NewCarbonCreditToken("Token1", 100, time.Now().Add(24*time.Hour))
	tracker.AddToken(token)

	// Consume a token
	err = tracker.ConsumeToken(token.ID, 10.5)
	if err != nil {
		fmt.Println("Error consuming token:", err)
		return
	}
	fmt.Printf("Token after consumption: %+v\n", token)
}
