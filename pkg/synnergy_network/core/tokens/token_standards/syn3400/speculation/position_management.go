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
	PositionID      string
	PairID          string
	HolderID        string
	PositionSize    float64
	OpenRate        float64
	LongShortStatus string
	OpenedDate      time.Time
	LastUpdatedDate time.Time
	CurrentValue    float64
}

// PositionManager manages speculative positions.
type PositionManager struct {
	Positions map[string]*Position
	mu        sync.Mutex
}

// NewPositionManager initializes a new PositionManager.
func NewPositionManager() *PositionManager {
	return &PositionManager{
		Positions: make(map[string]*Position),
	}
}

// OpenPosition opens a new speculative position.
func (pm *PositionManager) OpenPosition(pairID, holderID string, positionSize, openRate float64, longShortStatus string) (*Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	positionID := generateUniqueID()
	position := &Position{
		PositionID:      positionID,
		PairID:          pairID,
		HolderID:        holderID,
		PositionSize:    positionSize,
		OpenRate:        openRate,
		LongShortStatus: longShortStatus,
		OpenedDate:      time.Now(),
		LastUpdatedDate: time.Now(),
		CurrentValue:    positionSize * openRate,
	}

	pm.Positions[positionID] = position

	event := events.NewEventLogging()
	event.LogEvent("PositionOpened", fmt.Sprintf("Position %s opened for pair %s", positionID, pairID))

	return position, nil
}

// ClosePosition closes an existing speculative position.
func (pm *PositionManager) ClosePosition(positionID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.Positions[positionID]
	if !exists {
		return errors.New("position not found")
	}

	position.LastUpdatedDate = time.Now()
	position.CurrentValue = 0

	event := events.NewEventLogging()
	event.LogEvent("PositionClosed", fmt.Sprintf("Position %s closed", positionID))

	delete(pm.Positions, positionID)
	return nil
}

// UpdatePosition updates an existing speculative position with new values.
func (pm *PositionManager) UpdatePosition(positionID string, newRate float64) (*Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.Positions[positionID]
	if !exists {
		return nil, errors.New("position not found")
	}

	position.OpenRate = newRate
	position.LastUpdatedDate = time.Now()
	position.CurrentValue = position.PositionSize * newRate

	event := events.NewEventLogging()
	event.LogEvent("PositionUpdated", fmt.Sprintf("Position %s updated", positionID))

	return position, nil
}

// EvaluatePosition evaluates the current value of a speculative position.
func (pm *PositionManager) EvaluatePosition(positionID string) (float64, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	position, exists := pm.Positions[positionID]
	if !exists {
		return 0, errors.New("position not found")
	}

	return position.CurrentValue, nil
}

// ListPositions lists all active speculative positions.
func (pm *PositionManager) ListPositions() ([]*Position, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var positions []*Position
	for _, position := range pm.Positions {
		positions = append(positions, position)
	}
	return positions, nil
}

// generateUniqueID generates a unique identifier for positions.
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// EventLogging provides event logging functionalities.
type EventLogging struct {
}

// NewEventLogging initializes a new EventLogging instance.
func NewEventLogging() *EventLogging {
	return &EventLogging{}
}

// LogEvent logs an event with a given type and message.
func (el *EventLogging) LogEvent(eventType, message string) {
	event := map[string]interface{}{
		"event_type": eventType,
		"message":    message,
		"timestamp":  time.Now().UTC(),
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}
