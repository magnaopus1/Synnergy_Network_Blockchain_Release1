package loanpool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// RiskProfile defines the risk factors associated with a loan.
type RiskProfile struct {
	ProjectID    string  `json:"project_id"`
	CreditScore  int     `json:"credit_score"`
	LoanAmount   float64 `json:"loan_amount"`
	RepaymentTerm int    `json:"repayment_term"` // in months
	RiskScore    float64 `json:"risk_score"` // calculated risk based on factors
}

// RiskAssessor encapsulates risk assessment logic.
type RiskAssessor struct {
	encryptionKey []byte
}

// NewRiskAssessor creates a new RiskAssessor with the necessary encryption key.
func NewRiskAssessor(key []byte) *RiskAssessor {
	return &RiskAssessor{
		encryptionKey: key,
	}
}

// AssessRisk calculates the risk score based on the credit score, loan amount, and repayment term.
func (ra *RiskAssessor) AssessRisk(profile *RiskProfile) error {
	if profile.CreditScore < 300 || profile.CreditScore > 850 {
		return errors.New("invalid credit score range")
	}

	// Risk calculation formula (simplified example)
	baseRisk := 1000 - float64(profile.CreditScore)
	amountRisk := profile.LoanAmount / 1000
	timeRisk := float64(12) / float64(profile.RepaymentTerm)

	profile.RiskScore = baseRisk + amountRisk + timeRisk
	return nil
}

// EncryptProfile encrypts the risk profile for secure storage or transmission.
func (ra *RiskAssessor) EncryptProfile(profile *RiskProfile) ([]byte, error) {
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal risk profile")
	}

	block, err := aes.NewCipher(ra.encryptionKey)
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

// DecryptProfile decrypts the risk profile data.
func (ra *RiskAssessor) DecryptProfile(data []byte) (*RiskProfile, error) {
	block, err := aes.NewCipher(ra.encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("invalid data size")
	}

	nonce, encryptedData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	var profile RiskProfile
	if err := json.Unmarshal(decrypted, &profile); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal risk profile")
	}

	return &profile, nil
}
