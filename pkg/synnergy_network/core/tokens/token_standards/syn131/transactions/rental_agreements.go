package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
)

// RentalAgreement represents a rental agreement for SYN131 tokens.
type RentalAgreement struct {
	ID            string    `json:"id"`
	AssetID       string    `json:"asset_id"`
	Owner         string    `json:"owner"`
	Renter        string    `json:"renter"`
	StartDate     time.Time `json:"start_date"`
	EndDate       time.Time `json:"end_date"`
	RentAmount    float64   `json:"rent_amount"`
	Status        string    `json:"status"`
	TransactionHash string  `json:"transaction_hash"`
}

// RentalAgreementService provides services for managing rental agreements.
type RentalAgreementService struct {
	ledger   *ledger.TransactionLedger
	storage  *assets.AssetStorage
	security *security.SecurityService
}

// NewRentalAgreementService creates a new RentalAgreementService.
func NewRentalAgreementService(ledger *ledger.TransactionLedger, storage *assets.AssetStorage, security *security.SecurityService) *RentalAgreementService {
	return &RentalAgreementService{ledger: ledger, storage: storage, security: security}
}

// InitiateRentalAgreement initiates a rental agreement.
func (service *RentalAgreementService) InitiateRentalAgreement(assetID, owner, renter string, startDate, endDate time.Time, rentAmount float64) (*RentalAgreement, error) {
	if owner == renter {
		return nil, errors.New("owner and renter cannot be the same")
	}

	// Generate a unique ID for the rental agreement
	hash := sha256.New()
	hash.Write([]byte(assetID + owner + renter + startDate.String() + endDate.String() + time.Now().String()))
	id := hex.EncodeToString(hash.Sum(nil))

	// Generate a transaction hash
	transactionHash := service.generateTransactionHash(assetID, owner, renter, startDate, endDate, rentAmount)

	// Create the rental agreement object
	agreement := &RentalAgreement{
		ID:              id,
		AssetID:         assetID,
		Owner:           owner,
		Renter:          renter,
		StartDate:       startDate,
		EndDate:         endDate,
		RentAmount:      rentAmount,
		Status:          "pending",
		TransactionHash: transactionHash,
	}

	// Record the rental agreement in the ledger
	err := service.ledger.RecordRentalAgreement(agreement)
	if err != nil {
		return nil, err
	}

	return agreement, nil
}

// CompleteRentalAgreement completes a rental agreement.
func (service *RentalAgreementService) CompleteRentalAgreement(id string) error {
	agreement, err := service.GetRentalAgreement(id)
	if err != nil {
		return err
	}

	if agreement.Status != "pending" {
		return errors.New("agreement is not pending")
	}

	// Update the rental status
	agreement.Status = "active"
	return service.ledger.UpdateRentalAgreementStatus(id, "active")
}

// TerminateRentalAgreement terminates a rental agreement.
func (service *RentalAgreementService) TerminateRentalAgreement(id string) error {
	agreement, err := service.GetRentalAgreement(id)
	if err != nil {
		return err
	}

	if agreement.Status != "active" {
		return errors.New("agreement is not active")
	}

	// Update the rental status
	agreement.Status = "terminated"
	return service.ledger.UpdateRentalAgreementStatus(id, "terminated")
}

// GetRentalAgreement retrieves a rental agreement by ID.
func (service *RentalAgreementService) GetRentalAgreement(id string) (*RentalAgreement, error) {
	return service.ledger.GetRentalAgreementByID(id)
}

// ValidateRentalAgreement validates if a rental agreement is legitimate.
func (service *RentalAgreementService) ValidateRentalAgreement(id string) (bool, error) {
	agreement, err := service.GetRentalAgreement(id)
	if err != nil {
		return false, err
	}

	if agreement.Status != "pending" {
		return false, nil
	}

	return true, nil
}

// generateTransactionHash generates a hash for the transaction.
func (service *RentalAgreementService) generateTransactionHash(assetID, owner, renter string, startDate, endDate time.Time, rentAmount float64) string {
	hash := sha256.New()
	hash.Write([]byte(assetID + owner + renter + startDate.String() + endDate.String() + string(rentAmount) + time.Now().String()))
	return hex.EncodeToString(hash.Sum(nil))
}
