package contracts

import (
	"errors"
	"fmt"
	"time"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/smart_contracts"
)

// CoOwnershipAgreement represents a smart contract for co-ownership of an asset.
type CoOwnershipAgreement struct {
	AssetID        string
	CoOwners       map[string]float64 // Owner ID to share percentage
	CreationDate   time.Time
	AgreementTerms string
}

// CoOwnershipManager handles the creation and management of co-ownership agreements.
type CoOwnershipManager struct {
	Agreements map[string]*CoOwnershipAgreement
	Ledger     *ledger.LedgerManager
	Assets     *assets.OwnershipManager
}

// NewCoOwnershipManager initializes a new CoOwnershipManager.
func NewCoOwnershipManager(ledger *ledger.LedgerManager, assets *assets.OwnershipManager) *CoOwnershipManager {
	return &CoOwnershipManager{
		Agreements: make(map[string]*CoOwnershipAgreement),
		Ledger:     ledger,
		Assets:     assets,
	}
}

// CreateCoOwnershipAgreement creates a new co-ownership agreement.
func (com *CoOwnershipManager) CreateCoOwnershipAgreement(assetID string, coOwners map[string]float64, agreementTerms string) (*CoOwnershipAgreement, error) {
	if _, exists := com.Agreements[assetID]; exists {
		return nil, fmt.Errorf("co-ownership agreement for asset ID %s already exists", assetID)
	}

	totalShares := 0.0
	for _, share := range coOwners {
		totalShares += share
	}

	if totalShares > 100.0 {
		return nil, errors.New("total shares exceed 100%")
	}

	agreement := &CoOwnershipAgreement{
		AssetID:        assetID,
		CoOwners:       coOwners,
		CreationDate:   time.Now(),
		AgreementTerms: agreementTerms,
	}

	com.Agreements[assetID] = agreement

	// Record the creation of the co-ownership agreement in the ledger
	if err := com.Ledger.RecordAgreementCreation(agreement); err != nil {
		return nil, err
	}

	// Create the fractional ownership entry
	if _, err := com.Assets.CreateFractionalOwnership(assetID, coOwners); err != nil {
		return nil, err
	}

	return agreement, nil
}

// TransferCoOwnership transfers shares of a co-owned asset to a new owner.
func (com *CoOwnershipManager) TransferCoOwnership(assetID, fromOwner, toOwner string, sharePercentage float64) error {
	agreement, exists := com.Agreements[assetID]
	if !exists {
		return fmt.Errorf("co-ownership agreement for asset ID %s not found", assetID)
	}

	fromShares, fromExists := agreement.CoOwners[fromOwner]
	if !fromExists || fromShares < sharePercentage {
		return fmt.Errorf("insufficient shares for owner %s", fromOwner)
	}

	// Transfer the shares
	if err := com.Assets.TransferShares(assetID, fromOwner, toOwner, sharePercentage); err != nil {
		return err
	}

	// Update the co-ownership agreement
	agreement.CoOwners[fromOwner] -= sharePercentage
	if agreement.CoOwners[fromOwner] == 0 {
		delete(agreement.CoOwners, fromOwner)
	}

	agreement.CoOwners[toOwner] += sharePercentage

	// Record the transfer in the ledger
	if err := com.Ledger.RecordShareTransfer(assetID, fromOwner, toOwner, sharePercentage); err != nil {
		return err
	}

	return nil
}

// GetCoOwnershipAgreement retrieves the co-ownership agreement for a given asset ID.
func (com *CoOwnershipManager) GetCoOwnershipAgreement(assetID string) (*CoOwnershipAgreement, error) {
	agreement, exists := com.Agreements[assetID]
	if !exists {
		return nil, fmt.Errorf("co-ownership agreement for asset ID %s not found", assetID)
	}
	return agreement, nil
}

// AdjustShares allows authorized entities to manually adjust the shares of a co-owned asset.
func (com *CoOwnershipManager) AdjustShares(assetID string, newShares map[string]float64, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized share adjustment")
	}

	agreement, exists := com.GetCoOwnershipAgreement(assetID)
	if !exists {
		return fmt.Errorf("co-ownership agreement for asset ID %s not found", assetID)
	}

	totalShares := 0.0
	for _, share := range newShares {
		totalShares += share
	}

	if totalShares > 100.0 {
		return errors.New("total shares exceed 100%")
	}

	agreement.CoOwners = newShares

	// Adjust the shares in the fractional ownership
	if err := com.Assets.AdjustShares(assetID, newShares, authorized); err != nil {
		return err
	}

	// Record the adjustment in the ledger
	if err := com.Ledger.RecordShareAdjustment(assetID, newShares); err != nil {
		return err
	}

	return nil
}

// AnalyzeCoOwnership provides analysis tools for stakeholders to make informed decisions.
func (com *CoOwnershipManager) AnalyzeCoOwnership(assetID string) (map[string]float64, error) {
	return com.Assets.HistoricalShareAnalysis(assetID)
}

// SmartContractIntegration integrates co-ownership agreements with smart contracts for automation.
func (com *CoOwnershipManager) SmartContractIntegration(assetID, contractCode string) error {
	agreement, exists := com.GetCoOwnershipAgreement(assetID)
	if !exists {
		return fmt.Errorf("co-ownership agreement for asset ID %s not found", assetID)
	}

	// Deploy the smart contract
	sc := smart_contracts.NewSmartContract(contractCode, agreement.CoOwners)
	if err := sc.Deploy(); err != nil {
		return err
	}

	// Link the smart contract to the co-ownership agreement
	agreement.AgreementTerms = fmt.Sprintf("%s\nSmart Contract Address: %s", agreement.AgreementTerms, sc.Address)

	return nil
}
