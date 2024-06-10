package loanpool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
	"github.com/google/uuid"
)

// Loan represents a loan's attributes in the system.
type Loan struct {
	ID            uuid.UUID `json:"id"`
	BorrowerID    uuid.UUID `json:"borrower_id"`
	Amount        float64   `json:"amount"`
	InterestRate  float64   `json:"interest_rate"`
	DueDate       time.Time `json:"due_date"`
	Status        string    `json:"status"`
}

// LoanManager handles the creation, storage, and tracking of loans.
type LoanManager struct {
	loans         map[uuid.UUID]Loan
	encryptionKey []byte
}

// NewLoanManager initializes a new LoanManager with an encryption key.
func NewLoanManager(key []byte) *LoanManager {
	return &LoanManager{
		loans:         make(map[uuid.UUID]Loan),
		encryptionKey: key,
	}
}

// CreateLoan initializes a new loan with the given details and stores it in the manager.
func (lm *LoanManager) CreateLoan(borrowerID uuid.UUID, amount, interestRate float64, dueDate time.Time) (Loan, error) {
	newLoan := Loan{
		ID:            uuid.New(),
		BorrowerID:    borrowerID,
		Amount:        amount,
		InterestRate:  interestRate,
		DueDate:       dueDate,
		Status:        "active",
	}
	lm.loans[newLoan.ID] = newLoan
	log.Printf("Loan created: %v", newLoan.ID)
	return newLoan, nil
}

// UpdateLoanStatus updates the status of an existing loan.
func (lm *LoanManager) UpdateLoanStatus(loanID uuid.UUID, status string) error {
	if loan, exists := lm.loans[loanID]; exists {
		loan.Status = status
		lm.loans[loanID] = loan
		log.Printf("Updated loan %v status to %s", loanID, status)
		return nil
	}
	return errors.New("loan not found")
}

// EncryptLoanData encrypts the loan data for secure storage or communication.
func (lm *LoanManager) EncryptLoanData(loan Loan) ([]byte, error) {
	data, err := json.Marshal(loan)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal loan data")
	}

	block, err := aes.NewCipher(lm.encryptionKey)
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

// DecryptLoanData decrypts the loan data.
func (lm *LoanManager) DecryptLoanData(data []byte) (Loan, error) {
	block, err := aes.NewCipher(lm.encryptionKey)
	if err != nil {
		return Loan{}, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Loan{}, errors.Wrap(err, "failed to create GCM")
	}

	if len(data) < gcm.NonceSize() {
		return Loan{}, errors.New("invalid data size")
	}

	nonce, encryptedData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return Loan{}, errors.Wrap(err, "failed to decrypt data")
	}

	var loan Loan
	if err := json.Unmarshal(decrypted, &loan); err != nil {
		return Loan{}, errors.Wrap(err, "failed to unmarshal loan data")
	}

	return loan, nil
}
