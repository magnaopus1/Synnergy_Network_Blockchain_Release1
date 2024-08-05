package data_visualization

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RealTimeUpdate represents a single real-time update in the data visualization system.
type RealTimeUpdate struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// RealTimeUpdateManager manages real-time updates for data visualization.
type RealTimeUpdateManager struct {
	updates []RealTimeUpdate
	mu      sync.Mutex
	logger  *zap.Logger
}

// NewRealTimeUpdateManager creates a new RealTimeUpdateManager.
func NewRealTimeUpdateManager(logger *zap.Logger) *RealTimeUpdateManager {
	return &RealTimeUpdateManager{
		updates: make([]RealTimeUpdate, 0),
		logger:  logger,
	}
}

// AddUpdate adds a new real-time update to the manager.
func (rtum *RealTimeUpdateManager) AddUpdate(update RealTimeUpdate) {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	update.Timestamp = time.Now()
	rtum.updates = append(rtum.updates, update)
	rtum.logger.Info("Added new real-time update", zap.String("id", update.ID))
}

// GetUpdate retrieves a real-time update by its ID.
func (rtum *RealTimeUpdateManager) GetUpdate(id string) (*RealTimeUpdate, error) {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	for _, update := range rtum.updates {
		if update.ID == id {
			return &update, nil
		}
	}
	return nil, errors.New("update not found")
}

// RemoveUpdate removes a real-time update by its ID.
func (rtum *RealTimeUpdateManager) RemoveUpdate(id string) error {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	for i, update := range rtum.updates {
		if update.ID == id {
			rtum.updates = append(rtum.updates[:i], rtum.updates[i+1:]...)
			rtum.logger.Info("Removed real-time update", zap.String("id", id))
			return nil
		}
	}
	return errors.New("update not found")
}

// ListUpdates lists all real-time updates.
func (rtum *RealTimeUpdateManager) ListUpdates() []RealTimeUpdate {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	return rtum.updates
}

// SaveUpdatesToFile saves real-time updates to a specified file.
func (rtum *RealTimeUpdateManager) SaveUpdatesToFile(filename string) error {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	rtum.logger.Info("Saving real-time updates to file", zap.String("filename", filename))
	data, err := json.Marshal(rtum.updates)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadUpdatesFromFile loads real-time updates from a specified file.
func (rtum *RealTimeUpdateManager) LoadUpdatesFromFile(filename string) error {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	rtum.logger.Info("Loading real-time updates from file", zap.String("filename", filename))
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var updates []RealTimeUpdate
	err = json.Unmarshal(data, &updates)
	if err != nil {
		return err
	}

	rtum.updates = updates
	return nil
}

// BroadcastUpdates broadcasts the real-time updates to connected clients.
func (rtum *RealTimeUpdateManager) BroadcastUpdates() error {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	// Example implementation of broadcasting updates to clients
	// This can be extended with actual WebSocket or other communication mechanisms.
	for _, update := range rtum.updates {
		rtum.logger.Info("Broadcasting update", zap.String("id", update.ID), zap.Any("data", update.Data))
		// Actual broadcasting logic here (e.g., WebSocket, MQTT, etc.)
	}
	return nil
}

// SubscribeToUpdates allows clients to subscribe to real-time updates.
func (rtum *RealTimeUpdateManager) SubscribeToUpdates(clientID string) error {
	rtum.logger.Info("Client subscribed to updates", zap.String("clientID", clientID))
	// Example implementation of client subscription
	// This can be extended with actual subscription management logic.
	return nil
}

// UnsubscribeFromUpdates allows clients to unsubscribe from real-time updates.
func (rtum *RealTimeUpdateManager) UnsubscribeFromUpdates(clientID string) error {
	rtum.logger.Info("Client unsubscribed from updates", zap.String("clientID", clientID))
	// Example implementation of client unsubscription
	// This can be extended with actual unsubscription management logic.
	return nil
}

// GenerateUpdateStatistics generates basic statistics for the real-time updates.
func (rtum *RealTimeUpdateManager) GenerateUpdateStatistics() (map[string]float64, error) {
	rtum.mu.Lock()
	defer rtum.mu.Unlock()

	rtum.logger.Info("Generating update statistics")
	stats := make(map[string]float64)
	count := float64(len(rtum.updates))
	if count == 0 {
		return stats, nil
	}

	sum := 0.0
	for _, update := range rtum.updates {
		value, ok := update.Data["value"].(float64)
		if ok {
			sum += value
		}
	}

	stats["count"] = count
	stats["sum"] = sum
	stats["mean"] = sum / count
	stats["variance"] = rtum.calculateVariance(sum, count)
	stats["stddev"] = math.Sqrt(stats["variance"])

	return stats, nil
}

// calculateVariance calculates the variance of the real-time updates.
func (rtum *RealTimeUpdateManager) calculateVariance(sum, count float64) float64 {
	mean := sum / count
	variance := 0.0
	for _, update := range rtum.updates {
		value, ok := update.Data["value"].(float64)
		if ok {
			variance += math.Pow(value-mean, 2)
		}
	}
	return variance / count
}


