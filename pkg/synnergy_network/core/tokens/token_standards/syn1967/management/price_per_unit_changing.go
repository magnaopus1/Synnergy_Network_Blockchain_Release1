package management

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"pkg/synnergy_network/core/tokens/token_standards/syn1967/events"
)

// PricePerUnitChangeManager manages the price per unit changes for SYN1967 tokens
type PricePerUnitChangeManager struct {
	priceLogs map[string][]assets.PriceLog
	mutex     sync.RWMutex
}

// NewPricePerUnitChangeManager creates a new price per unit change manager
func NewPricePerUnitChangeManager() *PricePerUnitChangeManager {
	return &PricePerUnitChangeManager{
		priceLogs: make(map[string][]assets.PriceLog),
	}
}

// AdjustPricePerUnit adjusts the price per unit of a specific token
func (pcm *PricePerUnitChangeManager) AdjustPricePerUnit(tokenID string, newPrice float64) error {
	pcm.mutex.Lock()
	defer pcm.mutex.Unlock()

	priceLog := assets.PriceLog{
		Timestamp: time.Now(),
		Price:     newPrice,
	}

	pcm.priceLogs[tokenID] = append(pcm.priceLogs[tokenID], priceLog)

	// Emit price adjustment event
	events.EmitPriceAdjustmentEvent(tokenID, newPrice)

	return nil
}

// GetPriceLogs retrieves all price logs for a specific token
func (pcm *PricePerUnitChangeManager) GetPriceLogs(tokenID string) ([]assets.PriceLog, error) {
	pcm.mutex.RLock()
	defer pcm.mutex.RUnlock()

	priceLogs, exists := pcm.priceLogs[tokenID]
	if !exists {
		return nil, errors.New("no price logs found for the specified token")
	}

	return priceLogs, nil
}

// GetCurrentPrice retrieves the current price per unit for a specific token
func (pcm *PricePerUnitChangeManager) GetCurrentPrice(tokenID string) (float64, error) {
	pcm.mutex.RLock()
	defer pcm.mutex.RUnlock()

	priceLogs, exists := pcm.priceLogs[tokenID]
	if !exists || len(priceLogs) == 0 {
		return 0, errors.New("no price logs found for the specified token")
	}

	return priceLogs[len(priceLogs)-1].Price, nil
}

// GeneratePriceReport generates a report for the price changes of a specific token
func (pcm *PricePerUnitChangeManager) GeneratePriceReport(tokenID string) (string, error) {
	priceLogs, err := pcm.GetPriceLogs(tokenID)
	if err != nil {
		return "", err
	}

	report := "Price Per Unit Change Report\n"
	report += "----------------------------\n"
	report += fmt.Sprintf("Token ID: %s\n", tokenID)
	report += "Price Changes:\n"

	for _, log := range priceLogs {
		report += fmt.Sprintf("  - Timestamp: %s, Price: %.2f\n", log.Timestamp.String(), log.Price)
	}

	currentPrice, err := pcm.GetCurrentPrice(tokenID)
	if err != nil {
		return "", err
	}

	report += fmt.Sprintf("\nCurrent Price: %.2f\n", currentPrice)

	return report, nil
}

// AnalyzePriceTrends analyzes the price trends of a specific token over a given period
func (pcm *PricePerUnitChangeManager) AnalyzePriceTrends(tokenID string, startTime, endTime time.Time) ([]assets.PriceLog, error) {
	pcm.mutex.RLock()
	defer pcm.mutex.RUnlock()

	var trends []assets.PriceLog
	priceLogs, exists := pcm.priceLogs[tokenID]
	if !exists {
		return nil, errors.New("no price logs found for the specified token")
	}

	for _, log := range priceLogs {
		if log.Timestamp.After(startTime) && log.Timestamp.Before(endTime) {
			trends = append(trends, log)
		}
	}

	if len(trends) == 0 {
		return nil, errors.New("no price trends found for the specified period")
	}

	return trends, nil
}
