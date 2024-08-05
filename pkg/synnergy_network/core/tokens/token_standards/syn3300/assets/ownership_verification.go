package assets

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// OwnershipVerification represents the verification details of an ETF share
type OwnershipVerification struct {
	ETFID        string    `json:"etf_id"`
	ShareTokenID string    `json:"share_token_id"`
	Owner        string    `json:"owner"`
	Verified     bool      `json:"verified"`
	Timestamp    time.Time `json:"timestamp"`
}

// OwnershipVerificationService provides methods to verify ownership of ETF shares
type OwnershipVerificationService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewOwnershipVerificationService creates a new instance of OwnershipVerificationService
func NewOwnershipVerificationService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *OwnershipVerificationService {
	return &OwnershipVerificationService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// VerifyOwnership verifies the ownership of an ETF share token and records the verification in the ledger
func (s *OwnershipVerificationService) VerifyOwnership(etfID, shareTokenID, owner string) (*OwnershipVerification, error) {
	if etfID == "" || shareTokenID == "" || owner == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Check if the share token exists in the ledger
	ownershipRecord, err := s.ledgerService.GetOwnershipRecord(shareTokenID)
	if err != nil {
		return nil, err
	}

	// Verify ownership
	if ownershipRecord.ETFID != etfID || ownershipRecord.Owner != owner {
		return nil, errors.New("ownership verification failed")
	}

	verification := &OwnershipVerification{
		ETFID:        etfID,
		ShareTokenID: shareTokenID,
		Owner:        owner,
		Verified:     true,
		Timestamp:    time.Now(),
	}

	// Encrypt the verification record
	encryptedVerification, err := s.encryptionService.EncryptData(verification)
	if err != nil {
		return nil, err
	}

	// Record the verification in the ledger
	if err := s.ledgerService.RecordOwnershipVerification(encryptedVerification); err != nil {
		return nil, err
	}

	return verification, nil
}

// GetOwnershipVerification retrieves the verification details of an ETF share by its token ID
func (s *OwnershipVerificationService) GetOwnershipVerification(shareTokenID string) (*OwnershipVerification, error) {
	if shareTokenID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted verification record from the ledger
	encryptedVerification, err := s.ledgerService.GetOwnershipVerification(shareTokenID)
	if err != nil {
		return nil, err
	}

	// Decrypt the verification record
	verification, err := s.encryptionService.DecryptData(encryptedVerification)
	if err != nil {
		return nil, err
	}

	return verification, nil
}

// ListAllOwnershipVerifications retrieves a list of all ownership verifications
func (s *OwnershipVerificationService) ListAllOwnershipVerifications() ([]*OwnershipVerification, error) {
	// Retrieve all encrypted ownership verifications from the ledger
	encryptedVerifications, err := s.ledgerService.GetAllOwnershipVerifications()
	if err != nil {
		return nil, err
	}

	var verifications []*OwnershipVerification
	for _, encryptedVerification := range encryptedVerifications {
		verification, err := s.encryptionService.DecryptData(encryptedVerification)
		if err != nil {
			return nil, err
		}
		verifications = append(verifications, verification)
	}

	return verifications, nil
}

// EncryptionService handles encryption-related operations
type EncryptionService struct{}

// EncryptData encrypts the given data using the most secure method for the situation
func (e *EncryptionService) EncryptData(data interface{}) (string, error) {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encryptedData, err := encryption.Argon2Encrypt(serializedData)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts the given data using the most secure method for the situation
func (e *EncryptionService) DecryptData(encryptedData string) (*OwnershipVerification, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var verification OwnershipVerification
	if err := json.Unmarshal([]byte(decryptedData), &verification); err != nil {
		return nil, err
	}

	return &verification, nil
}
