package fractional_ownership

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// FractionalShare represents a fractional share of an ETF (SYN3300) token
type FractionalShare struct {
	ETFID        string    `json:"etf_id"`
	ShareTokenID string    `json:"share_token_id"`
	Owner        string    `json:"owner"`
	Fraction     float64   `json:"fraction"` // Fraction of the total ETF token (e.g., 0.25 for 1/4)
	Timestamp    time.Time `json:"timestamp"`
}

// FractionalShareService provides methods to manage fractional shares of ETFs
type FractionalShareService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewFractionalShareService creates a new instance of FractionalShareService
func NewFractionalShareService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *FractionalShareService {
	return &FractionalShareService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// CreateFractionalShare creates a new fractional share for an ETF
func (s *FractionalShareService) CreateFractionalShare(etfID, shareTokenID, owner string, fraction float64) (*FractionalShare, error) {
	if etfID == "" || shareTokenID == "" || owner == "" || fraction <= 0 || fraction > 1 {
		return nil, errors.New("invalid input parameters")
	}

	fractionalShare := &FractionalShare{
		ETFID:        etfID,
		ShareTokenID: shareTokenID,
		Owner:        owner,
		Fraction:     fraction,
		Timestamp:    time.Now(),
	}

	// Encrypt the fractional share
	encryptedFractionalShare, err := s.encryptionService.EncryptData(fractionalShare)
	if err != nil {
		return nil, err
	}

	// Record the fractional share in the ledger
	if err := s.ledgerService.RecordFractionalShare(encryptedFractionalShare); err != nil {
		return nil, err
	}

	return fractionalShare, nil
}

// TransferFractionalShare transfers fractional shares from one owner to another
func (s *FractionalShareService) TransferFractionalShare(etfID, fromOwner, toOwner string, fraction float64) (*FractionalShare, error) {
	if etfID == "" || fromOwner == "" || toOwner == "" || fraction <= 0 || fraction > 1 {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the fractional share from the ledger
	fractionalShare, err := s.ledgerService.GetFractionalShare(etfID, fromOwner)
	if err != nil {
		return nil, err
	}

	// Validate and update the fraction
	if fractionalShare.Fraction < fraction {
		return nil, errors.New("insufficient fractional shares to transfer")
	}

	fractionalShare.Fraction -= fraction
	fractionalShare.Timestamp = time.Now()

	// Encrypt the updated fractional share
	encryptedFractionalShare, err := s.encryptionService.EncryptData(fractionalShare)
	if err != nil {
		return nil, err
	}

	// Update the fractional share in the ledger
	if err := s.ledgerService.UpdateFractionalShare(encryptedFractionalShare); err != nil {
		return nil, err
	}

	// Create a new fractional share for the recipient
	newFractionalShare := &FractionalShare{
		ETFID:        etfID,
		ShareTokenID: fractionalShare.ShareTokenID,
		Owner:        toOwner,
		Fraction:     fraction,
		Timestamp:    time.Now(),
	}

	// Encrypt the new fractional share
	encryptedNewFractionalShare, err := s.encryptionService.EncryptData(newFractionalShare)
	if err != nil {
		return nil, err
	}

	// Record the new fractional share in the ledger
	if err := s.ledgerService.RecordFractionalShare(encryptedNewFractionalShare); err != nil {
		return nil, err
	}

	return newFractionalShare, nil
}

// GetFractionalShare retrieves a fractional share by its ETF ID and owner
func (s *FractionalShareService) GetFractionalShare(etfID, owner string) (*FractionalShare, error) {
	if etfID == "" || owner == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted fractional share from the ledger
	encryptedFractionalShare, err := s.ledgerService.GetFractionalShare(etfID, owner)
	if err != nil {
		return nil, err
	}

	// Decrypt the fractional share
	fractionalShare, err := s.encryptionService.DecryptData(encryptedFractionalShare)
	if err != nil {
		return nil, err
	}

	return fractionalShare, nil
}

// ListAllFractionalShares retrieves all fractional shares for a given ETF
func (s *FractionalShareService) ListAllFractionalShares(etfID string) ([]*FractionalShare, error) {
	if etfID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve all encrypted fractional shares from the ledger
	encryptedFractionalShares, err := s.ledgerService.GetAllFractionalShares(etfID)
	if err != nil {
		return nil, err
	}

	var fractionalShares []*FractionalShare
	for _, encryptedFractionalShare := range encryptedFractionalShares {
		fractionalShare, err := s.encryptionService.DecryptData(encryptedFractionalShare)
		if err != nil {
			return nil, err
		}
		fractionalShares = append(fractionalShares, fractionalShare)
	}

	return fractionalShares, nil
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
func (e *EncryptionService) DecryptData(encryptedData string) (*FractionalShare, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var fractionalShare FractionalShare
	if err := json.Unmarshal([]byte(decryptedData), &fractionalShare); err != nil {
		return nil, err
	}

	return &fractionalShare, nil
}
