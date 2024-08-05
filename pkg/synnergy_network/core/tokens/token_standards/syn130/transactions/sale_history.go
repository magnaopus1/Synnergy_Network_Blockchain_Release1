package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)

// SaleRecord represents a record of an asset sale.
type SaleRecord struct {
	ID             string
	AssetID        string
	Seller         string
	Buyer          string
	SalePrice      float64
	SaleDate       time.Time
	TransactionID  string
	EncryptedData  []byte
}

// SaleHistoryManager manages the sale history of assets.
type SaleHistoryManager struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityManager
}

// NewSaleHistoryManager initializes a new SaleHistoryManager.
func NewSaleHistoryManager(ledger *ledger.TransactionLedger, security *security.SecurityManager) *SaleHistoryManager {
	return &SaleHistoryManager{
		ledger:   ledger,
		security: security,
	}
}

// RecordSale records a new sale in the sale history.
func (shm *SaleHistoryManager) RecordSale(assetID, seller, buyer string, salePrice float64, transactionID string) (*SaleRecord, error) {
	if assetID == "" || seller == "" || buyer == "" || salePrice <= 0 || transactionID == "" {
		return nil, errors.New("invalid sale details")
	}

	saleRecord := &SaleRecord{
		ID:            utils.GenerateUUID(),
		AssetID:       assetID,
		Seller:        seller,
		Buyer:         buyer,
		SalePrice:     salePrice,
		SaleDate:      time.Now(),
		TransactionID: transactionID,
	}

	// Encrypt sale data
	encryptedData, err := shm.security.EncryptData([]byte(fmt.Sprintf("%v", saleRecord)))
	if err != nil {
		return nil, err
	}
	saleRecord.EncryptedData = encryptedData

	// Record the sale in the transaction ledger
	err = shm.ledger.RecordTransaction(saleRecord.ID, "SaleRecord", saleRecord)
	if err != nil {
		return nil, err
	}

	return saleRecord, nil
}

// GetSaleHistory retrieves the sale history for an asset.
func (shm *SaleHistoryManager) GetSaleHistory(assetID string) ([]*SaleRecord, error) {
	if assetID == "" {
		return nil, errors.New("invalid asset ID")
	}

	// Retrieve sale records from the transaction ledger
	transactions, err := shm.ledger.GetTransactionsByType("SaleRecord")
	if err != nil {
		return nil, err
	}

	var saleHistory []*SaleRecord
	for _, tx := range transactions {
		var saleRecord SaleRecord
		err := utils.FromJSON(tx.Data, &saleRecord)
		if err != nil {
			return nil, err
		}

		// Decrypt sale data
		decryptedData, err := shm.security.DecryptData(saleRecord.EncryptedData)
		if err != nil {
			return nil, err
		}
		err = utils.FromJSON(decryptedData, &saleRecord)
		if err != nil {
			return nil, err
		}

		if saleRecord.AssetID == assetID {
			saleHistory = append(saleHistory, &saleRecord)
		}
	}

	return saleHistory, nil
}

// DisplaySalePrice displays the current sale price of an asset.
func (shm *SaleHistoryManager) DisplaySalePrice(assetID string) (float64, error) {
	saleHistory, err := shm.GetSaleHistory(assetID)
	if err != nil {
		return 0, err
	}

	if len(saleHistory) == 0 {
		return 0, errors.New("no sale history found for asset")
	}

	// Return the latest sale price
	return saleHistory[len(saleHistory)-1].SalePrice, nil
}

// NotifySale updates subscribers with the latest sale information.
func (shm *SaleHistoryManager) NotifySale(saleRecord *SaleRecord) error {
	if saleRecord == nil {
		return errors.New("invalid sale record")
	}

	notification := fmt.Sprintf("New sale recorded: AssetID: %s, Seller: %s, Buyer: %s, Sale Price: %f, Date: %s",
		saleRecord.AssetID, saleRecord.Seller, saleRecord.Buyer, saleRecord.SalePrice, saleRecord.SaleDate.String())
	return utils.SendNotification(saleRecord.Buyer, "New Sale Recorded", notification)
}
