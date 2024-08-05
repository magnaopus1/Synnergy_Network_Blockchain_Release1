package transactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
)

// OwnershipTransfer manages the transfer of ownership for employment tokens
type OwnershipTransfer struct {
	transferPath  string
	security      *security.SecurityManager
	encryptionKey []byte
	ledger        *ledger.OwnershipRecords
}

// NewOwnershipTransfer initializes a new OwnershipTransfer instance
func NewOwnershipTransfer(transferPath string, security *security.SecurityManager, encryptionKey []byte, ledger *ledger.OwnershipRecords) (*OwnershipTransfer, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	transfer := &OwnershipTransfer{
		transferPath:  transferPath,
		security:      security,
		encryptionKey: encryptionKey,
		ledger:        ledger,
	}

	return transfer, nil
}

// TransferRecord represents a single transfer record
type TransferRecord struct {
	TransferID  string    `json:"transfer_id"`
	OldOwnerID  string    `json:"old_owner_id"`
	NewOwnerID  string    `json:"new_owner_id"`
	TokenID     string    `json:"token_id"`
	ContractID  string    `json:"contract_id"`
	Timestamp   time.Time `json:"timestamp"`
	Details     string    `json:"details"`
}

// SaveTransferRecord saves a transfer record to the transfer history
func (ot *OwnershipTransfer) SaveTransferRecord(record *TransferRecord) error {
	records, err := ot.LoadTransferHistory()
	if err != nil {
		return fmt.Errorf("failed to load transfer history: %w", err)
	}

	records = append(records, *record)
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal transfer records: %w", err)
	}

	encryptedData, err := ot.security.Encrypt(data, ot.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer data: %w", err)
	}

	err = os.WriteFile(ot.transferPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transfer data to history: %w", err)
	}

	// Update ledger
	err = ot.ledger.UpdateOwnership(record.TokenID, record.NewOwnerID)
	if err != nil {
		return fmt.Errorf("failed to update ledger: %w", err)
	}

	return nil
}

// LoadTransferHistory loads the transfer history
func (ot *OwnershipTransfer) LoadTransferHistory() ([]TransferRecord, error) {
	var records []TransferRecord

	encryptedData, err := os.ReadFile(ot.transferPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return records, nil
		}
		return nil, fmt.Errorf("failed to read transfer history: %w", err)
	}

	data, err := ot.security.Decrypt(encryptedData, ot.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt transfer data: %w", err)
	}

	err = json.Unmarshal(data, &records)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transfer records: %w", err)
	}

	return records, nil
}

// GetTransferByID retrieves a transfer record by ID
func (ot *OwnershipTransfer) GetTransferByID(transferID string) (*TransferRecord, error) {
	records, err := ot.LoadTransferHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer history: %w", err)
	}

	for _, record := range records {
		if record.TransferID == transferID {
			return &record, nil
		}
	}

	return nil, errors.New("transfer not found")
}

// GetTransfersByOldOwner retrieves all transfer records for a specific old owner
func (ot *OwnershipTransfer) GetTransfersByOldOwner(oldOwnerID string) ([]TransferRecord, error) {
	var oldOwnerRecords []TransferRecord

	records, err := ot.LoadTransferHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer history: %w", err)
	}

	for _, record := range records {
		if record.OldOwnerID == oldOwnerID {
			oldOwnerRecords = append(oldOwnerRecords, record)
		}
	}

	return oldOwnerRecords, nil
}

// GetTransfersByNewOwner retrieves all transfer records for a specific new owner
func (ot *OwnershipTransfer) GetTransfersByNewOwner(newOwnerID string) ([]TransferRecord, error) {
	var newOwnerRecords []TransferRecord

	records, err := ot.LoadTransferHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer history: %w", err)
	}

	for _, record := range records {
		if record.NewOwnerID == newOwnerID {
			newOwnerRecords = append(newOwnerRecords, record)
		}
	}

	return newOwnerRecords, nil
}

// GetTransfersByToken retrieves all transfer records for a specific token
func (ot *OwnershipTransfer) GetTransfersByToken(tokenID string) ([]TransferRecord, error) {
	var tokenRecords []TransferRecord

	records, err := ot.LoadTransferHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer history: %w", err)
	}

	for _, record := range records {
		if record.TokenID == tokenID {
			tokenRecords = append(tokenRecords, record)
		}
	}

	return tokenRecords, nil
}

// RemoveTransferRecord removes a transfer record by ID
func (ot *OwnershipTransfer) RemoveTransferRecord(transferID string) error {
	records, err := ot.LoadTransferHistory()
	if err != nil {
		return fmt.Errorf("failed to load transfer history: %w", err)
	}

	for i, record := range records {
		if record.TransferID == transferID {
			records = append(records[:i], records[i+1:]...)
			break
		}
	}

	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal transfer records: %w", err)
	}

	encryptedData, err := ot.security.Encrypt(data, ot.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer data: %w", err)
	}

	err = os.WriteFile(ot.transferPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transfer data to history: %w", err)
	}

	return nil
}

// ListAllTransfers lists all transfer records in the history
func (ot *OwnershipTransfer) ListAllTransfers() ([]TransferRecord, error) {
	return ot.LoadTransferHistory()
}
