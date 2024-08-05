package smart_contracts

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
)

// FairETFAllocation manages fair allocation of ETF shares using smart contracts
type FairETFAllocation struct {
	assetManager      *assets.AssetManager
	transactionLedger *ledger.TransactionService
}

// NewFairETFAllocation creates a new instance of FairETFAllocation
func NewFairETFAllocation(assetManager *assets.AssetManager, transactionLedger *ledger.TransactionService) *FairETFAllocation {
	return &FairETFAllocation{
		assetManager:      assetManager,
		transactionLedger: transactionLedger,
	}
}

// AllocateShares allocates ETF shares fairly among investors based on predefined criteria
func (fea *FairETFAllocation) AllocateShares(etfID string, investorShares map[string]float64) error {
	totalShares, err := fea.assetManager.GetTotalShares(etfID)
	if err != nil {
		return err
	}

	allocatedShares := 0.0

	for investorID, shares := range investorShares {
		if allocatedShares+shares > totalShares {
			return errors.New("insufficient shares to allocate")
		}

		err := fea.assetManager.UpdateInvestorShares(etfID, investorID, shares)
		if err != nil {
			return err
		}

		allocatedShares += shares

		transaction := transactions.TransactionRecord{
			ID:               generateTransactionID(),
			ETFID:            etfID,
			From:             "system",
			To:               investorID,
			Amount:           shares,
			Timestamp:        time.Now(),
			TransactionStatus: "completed",
		}

		err = fea.transactionLedger.AddTransactionRecord(transaction)
		if err != nil {
			return err
		}
	}

	return nil
}

// ValidateAllocation checks if the ETF share allocation is fair and within regulations
func (fea *FairETFAllocation) ValidateAllocation(etfID string) (bool, error) {
	investorShares, err := fea.assetManager.GetInvestorShares(etfID)
	if err != nil {
		return false, err
	}

	totalShares, err := fea.assetManager.GetTotalShares(etfID)
	if err != nil {
		return false, err
	}

	allocatedShares := 0.0

	for _, shares := range investorShares {
		allocatedShares += shares
	}

	if allocatedShares > totalShares {
		return false, errors.New("allocated shares exceed total shares")
	}

	return true, nil
}

// AdjustAllocation adjusts the share allocation if discrepancies are found
func (fea *FairETFAllocation) AdjustAllocation(etfID string) error {
	isValid, err := fea.ValidateAllocation(etfID)
	if err != nil {
		return err
	}

	if !isValid {
		investorShares, err := fea.assetManager.GetInvestorShares(etfID)
		if err != nil {
			return err
		}

		totalShares, err := fea.assetManager.GetTotalShares(etfID)
		if err != nil {
			return err
		}

		excessShares := allocatedShares - totalShares

		for investorID, shares := range investorShares {
			if shares > 0 {
				newShares := shares - (shares / allocatedShares) * excessShares
				err := fea.assetManager.UpdateInvestorShares(etfID, investorID, newShares)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}
