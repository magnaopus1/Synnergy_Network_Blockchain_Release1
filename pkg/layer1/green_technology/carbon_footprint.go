package green_technology

import (
	"errors"
	"log"
	"time"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Constants for environmental metrics
const (
	Salt            = "your-unique-salt" // Change to a secure, random value
	KeyLength       = 32
	EmissionFactor  = 0.5 // Average kg CO2 emitted per kWh consumed by the network
	ReportingPeriod = time.Hour * 24 * 30 // Monthly reporting cycle
)

// CarbonFootprint represents the data related to the carbon emissions of blockchain operations
type CarbonFootprint struct {
	Timestamp   time.Time
	EnergyUsage float64 // in kWh
	CO2Emissions float64 // in kg
}

// NewCarbonFootprint initializes a new Carbon Footprint tracking object
func NewCarbonFootprint(energyUsage float64) *CarbonFootprint {
	return &CarbonFootprint{
		Timestamp:   time.Now(),
		EnergyUsage: energyUsage,
		CO2Emissions: energyUsage * EmissionFactor,
	}
}

// EncryptData uses Argon2 for data encryption
func EncryptData(data []byte) ([]byte, error) {
	salt := []byte(Salt)
	key := argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
	return key, nil
}

// DecryptData uses Scrypt for data decryption
func DecryptData(data []byte) ([]byte, error) {
	dk, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// UpdateEmissions calculates the updated carbon emissions based on new energy usage data
func (cf *CarbonFootprint) UpdateEmissions(newEnergyUsage float64) error {
	if newEnergyUsage < 0 {
		return errors.New("energy usage cannot be negative")
	}
	cf.EnergyUsage += newEnergyUsage
	cf.CO2Emissions = cf.EnergyUsage * EmissionFactor
	cf.Timestamp = time.Now()
	return nil
}

// ReportEmissions logs the current state of carbon emissions
func (cf *CarbonFootprint) ReportEmissions() {
	log.Printf("Report at %s: %f kWh used, resulting in %f kg CO2 emissions.\n",
		cf.Timestamp.Format(time.RFC1123), cf.EnergyUsage, cf.CO2Emissions)
}

// main function to demonstrate the usage of CarbonFootprint struct
func main() {
	cf := NewCarbonFootprint(1000) // Initial energy usage in kWh
	err := cf.UpdateEmissions(500) // Simulate an update in energy consumption
	if err != nil {
		log.Fatal(err)
	}
	cf.ReportEmissions()
}
