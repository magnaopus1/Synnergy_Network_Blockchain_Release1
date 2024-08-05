package speculation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

// RateUpdateManager manages real-time rate updates for Forex pairs.
type RateUpdateManager struct {
	rates   map[string]float64
	mu      sync.Mutex
	clients []RateUpdateClient
}

// RateUpdateClient represents a client that provides rate updates.
type RateUpdateClient interface {
	GetRate(pairID string) (float64, error)
}

// NewRateUpdateManager initializes a new RateUpdateManager.
func NewRateUpdateManager(clients []RateUpdateClient) *RateUpdateManager {
	return &RateUpdateManager{
		rates:   make(map[string]float64),
		clients: clients,
	}
}

// UpdateRates updates the rates for all Forex pairs from all clients.
func (rum *RateUpdateManager) UpdateRates(pairs []string) error {
	rum.mu.Lock()
	defer rum.mu.Unlock()

	for _, pairID := range pairs {
		var latestRate float64
		var err error
		for _, client := range rum.clients {
			latestRate, err = client.GetRate(pairID)
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("failed to update rate for pair %s: %v", pairID, err)
		}
		rum.rates[pairID] = latestRate

		// Log rate update event
		event := events.NewEventLogging()
		event.LogEvent("RateUpdated", fmt.Sprintf("Rate updated for pair %s: %f", pairID, latestRate))
	}

	return nil
}

// GetRate retrieves the latest rate for a Forex pair.
func (rum *RateUpdateManager) GetRate(pairID string) (float64, error) {
	rum.mu.Lock()
	defer rum.mu.Unlock()

	rate, exists := rum.rates[pairID]
	if !exists {
		return 0, errors.New("rate not found for this pair")
	}

	return rate, nil
}

// ListAllRates lists all current rates for Forex pairs.
func (rum *RateUpdateManager) ListAllRates() map[string]float64 {
	rum.mu.Lock()
	defer rum.mu.Unlock()

	ratesCopy := make(map[string]float64)
	for pairID, rate := range rum.rates {
		ratesCopy[pairID] = rate
	}
	return ratesCopy
}

// ForexAPIClient implements the RateUpdateClient interface for a Forex API.
type ForexAPIClient struct {
	BaseURL string
	APIKey  string
}

// NewForexAPIClient initializes a new ForexAPIClient.
func NewForexAPIClient(baseURL, apiKey string) *ForexAPIClient {
	return &ForexAPIClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
	}
}

// GetRate fetches the rate for a Forex pair from the Forex API.
func (fac *ForexAPIClient) GetRate(pairID string) (float64, error) {
	url := fmt.Sprintf("%s/rates?pair=%s&apikey=%s", fac.BaseURL, pairID, fac.APIKey)
	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("error fetching rate for pair %s: %v", pairID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("non-200 response code: %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, fmt.Errorf("error decoding response for pair %s: %v", pairID, err)
	}

	rate, ok := data["rate"].(float64)
	if !ok {
		return 0, fmt.Errorf("invalid rate format for pair %s", pairID)
	}

	return rate, nil
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
