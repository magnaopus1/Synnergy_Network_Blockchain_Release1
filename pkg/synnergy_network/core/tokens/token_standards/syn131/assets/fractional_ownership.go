package assets

import (
	"errors"
	"fmt"
	"time"
)

// FractionalOwnership represents fractional ownership of an intangible asset.
type FractionalOwnership struct {
	AssetID       string
	OwnerShares   map[string]float64 // Maps owner ID to their share percentage
	TotalShares   float64
	ProfitRecords []ProfitRecord
}

// ProfitRecord represents a record of profit distribution.
type ProfitRecord struct {
	OwnerID   string
	Amount    float64
	Timestamp time.Time
}

// OwnershipManager handles operations related to fractional ownership.
type OwnershipManager struct {
	FractionalOwnerships map[string]*FractionalOwnership
}

// NewOwnershipManager initializes a new OwnershipManager.
func NewOwnershipManager() *OwnershipManager {
	return &OwnershipManager{
		FractionalOwnerships: make(map[string]*FractionalOwnership),
	}
}

// CreateFractionalOwnership creates a new fractional ownership entry.
func (om *OwnershipManager) CreateFractionalOwnership(assetID string, initialShares map[string]float64) (*FractionalOwnership, error) {
	if _, exists := om.FractionalOwnerships[assetID]; exists {
		return nil, fmt.Errorf("fractional ownership for asset ID %s already exists", assetID)
	}

	totalShares := 0.0
	for _, share := range initialShares {
		totalShares += share
	}

	if totalShares > 100.0 {
		return nil, errors.New("total shares exceed 100%")
	}

	fractionalOwnership := &FractionalOwnership{
		AssetID:     assetID,
		OwnerShares: initialShares,
		TotalShares: totalShares,
	}

	om.FractionalOwnerships[assetID] = fractionalOwnership
	return fractionalOwnership, nil
}

// TransferShares transfers shares from one owner to another.
func (om *OwnershipManager) TransferShares(assetID, fromOwner, toOwner string, sharePercentage float64) error {
	fractionalOwnership, exists := om.FractionalOwnerships[assetID]
	if !exists {
		return fmt.Errorf("fractional ownership for asset ID %s not found", assetID)
	}

	fromShares, fromExists := fractionalOwnership.OwnerShares[fromOwner]
	if !fromExists || fromShares < sharePercentage {
		return fmt.Errorf("insufficient shares for owner %s", fromOwner)
	}

	fractionalOwnership.OwnerShares[fromOwner] -= sharePercentage
	if fractionalOwnership.OwnerShares[fromOwner] == 0 {
		delete(fractionalOwnership.OwnerShares, fromOwner)
	}

	fractionalOwnership.OwnerShares[toOwner] += sharePercentage
	fractionalOwnership.TotalShares += 0 // To trigger recalculations if needed in the future

	return nil
}

// DistributeProfits distributes profits among co-owners based on their share percentages.
func (om *OwnershipManager) DistributeProfits(assetID string, totalProfit float64) error {
	fractionalOwnership, exists := om.FractionalOwnerships[assetID]
	if !exists {
		return fmt.Errorf("fractional ownership for asset ID %s not found", assetID)
	}

	for owner, share := range fractionalOwnership.OwnerShares {
		profit := (share / 100.0) * totalProfit
		profitRecord := ProfitRecord{
			OwnerID:   owner,
			Amount:    profit,
			Timestamp: time.Now(),
		}
		fractionalOwnership.ProfitRecords = append(fractionalOwnership.ProfitRecords, profitRecord)
	}

	return nil
}

// GetOwnershipDetails retrieves the details of fractional ownership for a given asset ID.
func (om *OwnershipManager) GetOwnershipDetails(assetID string) (*FractionalOwnership, error) {
	fractionalOwnership, exists := om.FractionalOwnerships[assetID]
	if !exists {
		return nil, fmt.Errorf("fractional ownership for asset ID %s not found", assetID)
	}
	return fractionalOwnership, nil
}

// GetProfitRecords retrieves the profit distribution records for a given asset ID.
func (om *OwnershipManager) GetProfitRecords(assetID string) ([]ProfitRecord, error) {
	fractionalOwnership, exists := om.FractionalOwnerships[assetID]
	if !exists {
		return nil, fmt.Errorf("fractional ownership for asset ID %s not found", assetID)
	}
	return fractionalOwnership.ProfitRecords, nil
}

// AdjustShares allows authorized entities to manually adjust the shares of an asset.
func (om *OwnershipManager) AdjustShares(assetID string, newShares map[string]float64, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized share adjustment")
	}

	fractionalOwnership, exists := om.FractionalOwnerships[assetID]
	if !exists {
		return fmt.Errorf("fractional ownership for asset ID %s not found", assetID)
	}

	totalShares := 0.0
	for _, share := range newShares {
		totalShares += share
	}

	if totalShares > 100.0 {
		return errors.New("total shares exceed 100%")
	}

	fractionalOwnership.OwnerShares = newShares
	fractionalOwnership.TotalShares = totalShares

	return nil
}

// HistoricalShareAnalysis provides analysis tools for stakeholders to make informed decisions.
func (om *OwnershipManager) HistoricalShareAnalysis(assetID string) (map[string]float64, error) {
	fractionalOwnership, exists := om.GetOwnershipDetails(assetID)
	if !exists {
		return nil, fmt.Errorf("fractional ownership for asset ID %s not found", assetID)
	}

	// Example analysis: calculate total distributed profits for each owner
	profitDistribution := make(map[string]float64)
	for _, record := range fractionalOwnership.ProfitRecords {
		profitDistribution[record.OwnerID] += record.Amount
	}

	return profitDistribution, nil
}
