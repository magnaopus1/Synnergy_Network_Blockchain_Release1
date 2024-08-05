package management

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/smart_contracts"
)

type UserInterface struct {
	assetManager        *assets.AssetManager
	transactionLedger   *ledger.TransactionService
	encryptionService   *encryption.EncryptionService
	contractManager     *SmartContractManager
}

// NewUserInterface creates a new instance of UserInterface
func NewUserInterface(assetManager *assets.AssetManager, transactionLedger *ledger.TransactionService, encryptionService *encryption.EncryptionService, contractManager *SmartContractManager) *UserInterface {
	return &UserInterface{
		assetManager:      assetManager,
		transactionLedger: transactionLedger,
		encryptionService: encryptionService,
		contractManager:   contractManager,
	}
}

// CreateETF creates a new ETF with given metadata
func (ui *UserInterface) CreateETF(metadata assets.ETFMetadata) (string, error) {
	metadata.ID = generateETFID()
	metadata.CreatedAt = time.Now()
	metadata.UpdatedAt = time.Now()

	encryptedMetadata, err := ui.encryptionService.EncryptData(metadata)
	if err != nil {
		return "", err
	}

	err = ui.assetManager.AddETF(encryptedMetadata)
	if err != nil {
		return "", err
	}

	return metadata.ID, nil
}

// GetETF retrieves ETF metadata by ETF ID
func (ui *UserInterface) GetETF(etfID string) (*assets.ETFMetadata, error) {
	encryptedMetadata, err := ui.assetManager.GetETF(etfID)
	if err != nil {
		return nil, err
	}

	decryptedMetadata, err := ui.encryptionService.DecryptData(encryptedMetadata)
	if err != nil {
		return nil, err
	}

	return &decryptedMetadata, nil
}

// TransferETF transfers ETF shares from one owner to another
func (ui *UserInterface) TransferETF(etfID string, from string, to string, shares int) error {
	ownership, err := ui.assetManager.GetOwnership(etfID, from)
	if err != nil {
		return err
	}

	if ownership.Shares < shares {
		return errors.New("insufficient shares")
	}

	// Update ownership
	err = ui.assetManager.UpdateOwnership(etfID, from, -shares)
	if err != nil {
		return err
	}

	err = ui.assetManager.UpdateOwnership(etfID, to, shares)
	if err != nil {
		return err
	}

	// Record the transaction
	transaction := transactions.TransactionRecord{
		ID:            generateTransactionID(),
		ETFID:         etfID,
		From:          from,
		To:            to,
		Shares:        shares,
		Timestamp:     time.Now(),
		TransactionStatus: "completed",
	}

	err = ui.transactionLedger.AddTransactionRecord(transaction)
	if err != nil {
		return err
	}

	return nil
}

// ExecuteSmartContract executes a smart contract operation
func (ui *UserInterface) ExecuteSmartContract(contractID string, operation string, params map[string]interface{}) (interface{}, error) {
	result, err := ui.contractManager.ExecuteSmartContract(contractID, operation, params)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetTransactionHistory retrieves the transaction history for a given ETF
func (ui *UserInterface) GetTransactionHistory(etfID string) ([]transactions.TransactionRecord, error) {
	records, err := ui.transactionLedger.GetTransactionRecordsByETF(etfID)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// generateETFID generates a unique ETF ID
func generateETFID() string {
	return fmt.Sprintf("etf_%d", time.Now().UnixNano())
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}
