package verification_tracking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/carbon_credit_system"
)

// EmissionData represents emission data to be verified.
type EmissionData struct {
	DeviceID    string
	Timestamp   time.Time
	CO2Emission float64
	Verified    bool
	Hash        string
}

// CarbonReductionClaim represents a carbon reduction claim.
type CarbonReductionClaim struct {
	ClaimID       string
	EmissionData  EmissionData
	Verified      bool
	VerifierID    string
	VerificationTime time.Time
}

// CarbonCreditVerification represents the verification system for carbon credits.
type CarbonCreditVerification struct {
	claims map[string]*CarbonReductionClaim
	tokens map[string]*carbon_credit_system.CarbonCreditToken
}

// NewCarbonCreditVerification creates a new CarbonCreditVerification instance.
func NewCarbonCreditVerification() *CarbonCreditVerification {
	return &CarbonCreditVerification{
		claims: make(map[string]*CarbonReductionClaim),
		tokens: make(map[string]*carbon_credit_system.CarbonCreditToken),
	}
}

// AddToken adds a new carbon credit token to the verification system.
func (ccv *CarbonCreditVerification) AddToken(token *carbon_credit_system.CarbonCreditToken) {
	ccv.tokens[token.ID] = token
}

// SubmitClaim submits a new carbon reduction claim.
func (ccv *CarbonCreditVerification) SubmitClaim(data EmissionData, verifierID string) (*CarbonReductionClaim, error) {
	if !ccv.validateEmissionData(data) {
		return nil, errors.New("invalid emission data")
	}

	claimID, err := generateUniqueID()
	if err != nil {
		return nil, err
	}

	claim := &CarbonReductionClaim{
		ClaimID:       claimID,
		EmissionData:  data,
		Verified:      false,
		VerifierID:    verifierID,
		VerificationTime: time.Time{},
	}

	ccv.claims[claimID] = claim
	return claim, nil
}

// VerifyClaim verifies a submitted carbon reduction claim.
func (ccv *CarbonCreditVerification) VerifyClaim(claimID, verifierID string) error {
	claim, exists := ccv.claims[claimID]
	if !exists {
		return errors.New("claim not found")
	}

	if claim.Verified {
		return errors.New("claim already verified")
	}

	token, tokenExists := ccv.tokens[claim.EmissionData.DeviceID]
	if !tokenExists || token.IsRetired {
		return errors.New("invalid or retired token")
	}

	claim.Verified = true
	claim.VerificationTime = time.Now()
	claim.VerifierID = verifierID

	token.Amount -= claim.EmissionData.CO2Emission
	if token.Amount <= 0 {
		token.IsRetired = true
	}

	return nil
}

// validateEmissionData validates the emission data.
func (ccv *CarbonCreditVerification) validateEmissionData(data EmissionData) bool {
	calculatedHash := calculateHash(data)
	return data.Hash == calculatedHash
}

// calculateHash calculates the hash for the emission data.
func calculateHash(data EmissionData) string {
	record := fmt.Sprintf("%s:%s:%f", data.DeviceID, data.Timestamp.String(), data.CO2Emission)
	hash := sha256.New()
	hash.Write([]byte(record))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// generateUniqueID generates a unique identifier.
func generateUniqueID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func main() {
	verificationSystem := NewCarbonCreditVerification()

	// Example usage
	token, _ := carbon_credit_system.NewCarbonCreditToken("Device1", 100, time.Now().Add(24*time.Hour))
	verificationSystem.AddToken(token)

	emissionData := EmissionData{
		DeviceID:    "Device1",
		Timestamp:   time.Now(),
		CO2Emission: 10,
		Hash:        calculateHash(EmissionData{DeviceID: "Device1", Timestamp: time.Now(), CO2Emission: 10}),
	}

	claim, err := verificationSystem.SubmitClaim(emissionData, "Verifier1")
	if err != nil {
		fmt.Println("Error submitting claim:", err)
		return
	}

	err = verificationSystem.VerifyClaim(claim.ClaimID, "Verifier1")
	if err != nil {
		fmt.Println("Error verifying claim:", err)
		return
	}

	fmt.Printf("Claim verified: %+v\n", claim)
}
