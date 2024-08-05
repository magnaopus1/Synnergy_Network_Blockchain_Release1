package speculation

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

// Position represents a speculative position on a Forex pair.
type Position struct {
	ID        string    `json:"id"`
	PairID    string    `json:"pair_id"`
	Holder    string    `json:"holder"`
	Size      float64   `json:"size"`
	OpenRate  float64   `json:"open_rate"`
	Status    string    `json:"status"` // "long" or "short"
	OpenedAt  time.Time `json:"opened_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PositionManager manages speculative positions on Forex pairs.
type PositionManager struct {
	positions map[string]Position
	mu        sync.Mutex
}

// NewPositionManager initializes a new PositionManager.
func NewPositionManager() *PositionManager {
	return &PositionManager{
		positions: make(map[string]Position),
	}
}

// OpenPosition opens a new speculative position.
func (pm *PositionManager) OpenPosition(pairID, holder string, size, openRate float64, status string) (Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if status != "long" && status != "short" {
		return Position{}, errors.New("invalid position status, must be 'long' or 'short'")
	}

	positionID := fmt.Sprintf("%s-%s-%d", holder, pairID, time.Now().UnixNano())
	position := Position{
		ID:        positionID,
		PairID:    pairID,
		Holder:    holder,
		Size:      size,
		OpenRate:  openRate,
		Status:    status,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	pm.positions[positionID] = position

	// Log position opening event
	event := events.NewEventLogging()
	event.LogEvent("PositionOpened", fmt.Sprintf("Position opened: %+v", position))

	return position, nil
}

// ClosePosition closes an existing speculative position.
func (pm *PositionManager) ClosePosition(positionID string) (Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.positions[positionID]
	if !exists {
		return Position{}, errors.New("position not found")
	}

	delete(pm.positions, positionID)

	// Log position closing event
	event := events.NewEventLogging()
	event.LogEvent("PositionClosed", fmt.Sprintf("Position closed: %+v", position))

	return position, nil
}

// UpdatePosition updates an existing speculative position.
func (pm *PositionManager) UpdatePosition(positionID string, size, openRate float64, status string) (Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.positions[positionID]
	if !exists {
		return Position{}, errors.New("position not found")
	}

	if status != "long" && status != "short" {
		return Position{}, errors.New("invalid position status, must be 'long' or 'short'")
	}

	position.Size = size
	position.OpenRate = openRate
	position.Status = status
	position.UpdatedAt = time.Now().UTC()

	pm.positions[positionID] = position

	// Log position update event
	event := events.NewEventLogging()
	event.LogEvent("PositionUpdated", fmt.Sprintf("Position updated: %+v", position))

	return position, nil
}

// GetPosition retrieves a speculative position by ID.
func (pm *PositionManager) GetPosition(positionID string) (Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.positions[positionID]
	if !exists {
		return Position{}, errors.New("position not found")
	}

	return position, nil
}

// ListAllPositions lists all current speculative positions.
func (pm *PositionManager) ListAllPositions() []Position {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	positions := make([]Position, 0, len(pm.positions))
	for _, position := range pm.positions {
		positions = append(positions, position)
	}
	return positions
}

// CalculateProfitLoss calculates the profit or loss for a speculative position.
func (pm *PositionManager) CalculateProfitLoss(positionID string, currentRate float64) (float64, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.positions[positionID]
	if !exists {
		return 0, errors.New("position not found")
	}

	var profitLoss float64
	if position.Status == "long" {
		profitLoss = (currentRate - position.OpenRate) * position.Size
	} else if position.Status == "short" {
		profitLoss = (position.OpenRate - currentRate) * position.Size
	} else {
		return 0, errors.New("invalid position status")
	}

	return profitLoss, nil
}
