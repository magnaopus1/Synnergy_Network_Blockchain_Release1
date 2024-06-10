package loanpool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"math"

	"github.com/pkg/errors"
)

// BorrowerDetails holds the necessary financial details of the borrower.
type BorrowerDetails struct {
	AnnualIncome    float64 `json:"annual_income"`
	ExistingDebts   float64 `json:"existing_debts"`
	CreditScore     int     `json:"credit_score"`
	RequestedAmount float64 `json:"requested_amount"`
}

// AffordabilityCheck encapsulates the logic for determining loan affordability.
type AffordabilityCheck struct {
	encryptionKey []byte
}

// NewAffordabilityCheck creates a new instance of AffordabilityCheck with a specified encryption key.
func NewAffordabilityCheck(key []byte) *AffordabilityCheck {
	return &AffordabilityCheck{
		encryptionKey: key,
	}
}

// CalculateDebtToIncomeRatio calculates the Debt to Income Ratio, a key indicator of affordability.
func (ac *AffordabilityCheck) CalculateDebtToIncomeRatio(details BorrowerDetails) float64 {
	if details.AnnualIncome == 0 {
		return math.Inf(1) // Returns positive infinity if income is zero to indicate no affordability
	}
	return (details.ExistingDebts / details.AnnualIncome) * 100
}

// EvaluateCreditRisk assesses if the borrower is a credit risk based on their credit score and DTI ratio.
func (ac *AffordabilityCheck) EvaluateCreditRisk(details BorrowerDetails) (bool, error) {
	dti := ac.CalculateDebtToIncomeRatio(details)
	if dti > 40 || details.CreditScore < 620 {
		log.Println("High credit risk identified.")
		return false, nil
	}
	return true, nil
}

// PerformAffordabilityCheck conducts a comprehensive check to determine if a loan is affordable for the borrower.
func (ac *AffordabilityCheck) PerformAffordabilityCheck(details BorrowerDetails) (bool, error) {
	affordable, err := ac.EvaluateCreditRisk(details)
	if err != nil {
		return false, errors.Wrap(err, "failed to evaluate credit risk")
	}

	if !affordable {
		log.Println("Loan not affordable for the borrower based on current financial standing.")
		return false, nil
	}

	return true, nil
}

// EncryptBorrowerDetails securely encrypts borrower's details.
func (ac *AffordabilityCheck) EncryptBorrowerDetails(details BorrowerDetails) ([]byte, error) {
	data, err := json.Marshal(details)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal borrower details")
	}

	block, err := aes.NewCipher(ac.encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to create nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// DecryptBorrowerDetails decrypts the encrypted borrower details.
func (ac *AffordabilityCheck) DecryptBorrowerDetails(encryptedData []byte) (BorrowerDetails, error) {
	block, err := aes.NewCipher(ac.encryptionKey)
	if err != nil {
		return BorrowerDetails{}, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return BorrowerDetails{}, errors.Wrap(err, "failed to create GCM")
	}

	if len(encryptedData) < gcm.NonceSize() {
		return BorrowerDetails{}, errors.New("encrypted data too short")
	}

	nonce, cipherText := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return BorrowerDetails{}, errors.Wrap(err, "failed to decrypt data")
	}

	var details BorrowerDetails
	if err := json.Unmarshal(decrypted, &details); err != nil {
		return BorrowerDetails{}, errors.Wrap(err, "failed to unmarshal borrower details")
	}

	return details, nil
}
