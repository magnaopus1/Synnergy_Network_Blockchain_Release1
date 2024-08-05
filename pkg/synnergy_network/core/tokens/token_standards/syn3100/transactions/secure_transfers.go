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

// SecureTransfers manages the secure transfer of employment tokens
type SecureTransfers struct {
	transferPath  string
	security      *security.SecurityManager
	encryptionKey []byte
	ledger        *ledger.EmploymentTransactionLedger
}

// NewSecureTransfers initializes a new SecureTransfers instance
func NewSecureTransfers(transferPath string, security *security.SecurityManager, encryptionKey []byte, ledger *ledger.EmploymentTransactionLedger) (*SecureTransfers, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	transfer := &SecureTransfers{
		transferPath:  transferPath,
		security:      security,
		encryptionKey: encryptionKey,
		ledger:        ledger,
	}

	return transfer, nil
}

// TransferRecord represents a single secure transfer record
type TransferRecord struct {
	TransferID   string    `json:"transfer_id"`
	SenderID     string    `json:"sender_id"`
	ReceiverID   string    `json:"receiver_id"`
	TokenID      string    `json:"token_id"`
	ContractID   string    `json:"contract_id"`
	Timestamp    time.Time `json:"timestamp"`
	Details      string    `json:"details"`
	EncryptedKey []byte    `json:"encrypted_key"`
}

// SaveTransferRecord saves a secure transfer record to the transfer history
func (st *SecureTransfers) SaveTransferRecord(record *TransferRecord) error {
	records, err := st.LoadTransferHistory()
	if err != nil {
		return fmt.Errorf("failed to load transfer history: %w", err)
	}

	records = append(records, *record)
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal transfer records: %w", err)
	}

	encryptedData, err := st.security.Encrypt(data, st.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer data: %w", err)
	}

	err = os.WriteFile(st.transferPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transfer data to history: %w", err)
	}

	// Update ledger
	err = st.ledger.AddTransaction(record.TransferID, record.SenderID, record.ReceiverID, record.TokenID, record.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to update ledger: %w", err)
	}

	return nil
}

// LoadTransferHistory loads the secure transfer history
func (st *SecureTransfers) LoadTransferHistory() ([]TransferRecord, error) {
	var records []TransferRecord

	encryptedData, err := os.ReadFile(st.transferPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return records, nil
		}
		return nil, fmt.Errorf("failed to read transfer history: %w", err)
	}

	data, err := st.security.Decrypt(encryptedData, st.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt transfer data: %w", err)
	}

	err = json.Unmarshal(data, &records)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transfer records: %w", err)
	}

	return records, nil
}

// GetTransferByID retrieves a secure transfer record by ID
func (st *SecureTransfers) GetTransferByID(transferID string) (*TransferRecord, error) {
	records, err := st.LoadTransferHistory()
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

// GetTransfersBySender retrieves all secure transfer records for a specific sender
func (st *SecureTransfers) GetTransfersBySender(senderID string) ([]TransferRecord, error) {
	var senderRecords []TransferRecord

	records, err := st.LoadTransferHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer history: %w", err)
	}

	for _, record := range records {
		if record.SenderID == senderID {
			senderRecords = append(senderRecords, record)
		}
	}

	return senderRecords, nil
}

// GetTransfersByReceiver retrieves all secure transfer records for a specific receiver
func (st *SecureTransfers) GetTransfersByReceiver(receiverID string) ([]TransferRecord, error) {
	var receiverRecords []TransferRecord

	records, err := st.LoadTransferHistory()
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer history: %w", err)
	}

	for _, record := range records {
		if record.ReceiverID == receiverID {
			receiverRecords = append(receiverRecords, record)
		}
	}

	return receiverRecords, nil
}

// GetTransfersByToken retrieves all secure transfer records for a specific token
func (st *SecureTransfers) GetTransfersByToken(tokenID string) ([]TransferRecord, error) {
	var tokenRecords []TransferRecord

	records, err := st.LoadTransferHistory()
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

// RemoveTransferRecord removes a secure transfer record by ID
func (st *SecureTransfers) RemoveTransferRecord(transferID string) error {
	records, err := st.LoadTransferHistory()
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

	encryptedData, err := st.security.Encrypt(data, st.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer data: %w", err)
	}

	err = os.WriteFile(st.transferPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transfer data to history: %w", err)
	}

	return nil
}

// ListAllTransfers lists all secure transfer records in the history
func (st *SecureTransfers) ListAllTransfers() ([]TransferRecord, error) {
	return st.LoadTransferHistory()
}
