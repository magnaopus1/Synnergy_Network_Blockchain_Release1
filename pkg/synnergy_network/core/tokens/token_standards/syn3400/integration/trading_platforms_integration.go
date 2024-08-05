package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

type TradingPlatformIntegration struct {
	Platforms       map[string]TradingPlatform
	mutex           sync.Mutex
	EventLogger     *events.EventLogging
}

type TradingPlatform struct {
	PlatformID   string    `json:"platform_id"`
	Name         string    `json:"name"`
	Endpoint     string    `json:"endpoint"`
	APIKey       string    `json:"api_key"`
	LastConnected time.Time `json:"last_connected"`
}

// InitializeTradingPlatformIntegration initializes the TradingPlatformIntegration structure
func InitializeTradingPlatformIntegration() *TradingPlatformIntegration {
	return &TradingPlatformIntegration{
		Platforms:   make(map[string]TradingPlatform),
		EventLogger: events.InitializeEventLogging(),
	}
}

// AddTradingPlatform adds a new trading platform to the integration system
func (tpi *TradingPlatformIntegration) AddTradingPlatform(platformID, name, endpoint, apiKey string) error {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	if _, exists := tpi.Platforms[platformID]; exists {
		return errors.New("trading platform already exists")
	}

	tpi.Platforms[platformID] = TradingPlatform{
		PlatformID:   platformID,
		Name:         name,
		Endpoint:     endpoint,
		APIKey:       apiKey,
		LastConnected: time.Time{},
	}

	tpi.EventLogger.LogEvent(fmt.Sprintf("platform-added-%s", platformID), "PLATFORM_ADDED", fmt.Sprintf("Added trading platform: %s", name))

	return nil
}

// RemoveTradingPlatform removes a trading platform from the integration system
func (tpi *TradingPlatformIntegration) RemoveTradingPlatform(platformID string) error {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	if _, exists := tpi.Platforms[platformID]; !exists {
		return errors.New("trading platform not found")
	}

	delete(tpi.Platforms, platformID)

	tpi.EventLogger.LogEvent(fmt.Sprintf("platform-removed-%s", platformID), "PLATFORM_REMOVED", fmt.Sprintf("Removed trading platform: %s", platformID))

	return nil
}

// GetTradingPlatform retrieves information about a trading platform
func (tpi *TradingPlatformIntegration) GetTradingPlatform(platformID string) (TradingPlatform, error) {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	platform, exists := tpi.Platforms[platformID]
	if !exists {
		return TradingPlatform{}, errors.New("trading platform not found")
	}

	return platform, nil
}

// ConnectToPlatform connects to a trading platform and updates the last connected time
func (tpi *TradingPlatformIntegration) ConnectToPlatform(platformID string) error {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	platform, exists := tpi.Platforms[platformID]
	if !exists {
		return errors.New("trading platform not found")
	}

	// Simulate connecting to the trading platform
	platform.LastConnected = time.Now()
	tpi.Platforms[platformID] = platform

	tpi.EventLogger.LogEvent(fmt.Sprintf("platform-connected-%s", platformID), "PLATFORM_CONNECTED", fmt.Sprintf("Connected to trading platform: %s", platform.Name))

	return nil
}

// RelayTransactionToPlatform relays a transaction to a trading platform
func (tpi *TradingPlatformIntegration) RelayTransactionToPlatform(platformID string, transaction transactions.Transaction) error {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	platform, exists := tpi.Platforms[platformID]
	if !exists {
		return errors.New("trading platform not found")
	}

	// Create the request payload
	payload, err := json.Marshal(transaction)
	if err != nil {
		return err
	}

	// Send the transaction to the trading platform
	req, err := http.NewRequest("POST", platform.Endpoint+"/relay", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", platform.APIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("failed to relay transaction with status code: %d", resp.StatusCode))
	}

	tpi.EventLogger.LogEvent(fmt.Sprintf("transaction-relayed-%s-%s", platformID, transaction.TransactionID), "TRANSACTION_RELAYED", fmt.Sprintf("Transaction relayed to platform: %s", platform.Name))

	return nil
}

// SavePlatformsToFile saves the trading platforms information to a file
func (tpi *TradingPlatformIntegration) SavePlatformsToFile(filename string) error {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	data, err := json.Marshal(tpi.Platforms)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadPlatformsFromFile loads the trading platforms information from a file
func (tpi *TradingPlatformIntegration) LoadPlatformsFromFile(filename string) error {
	tpi.mutex.Lock()
	defer tpi.mutex.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &tpi.Platforms)
}

// DisplayTradingPlatform displays the information of a trading platform in a readable format
func (tpi *TradingPlatformIntegration) DisplayTradingPlatform(platformID string) error {
	platform, err := tpi.GetTradingPlatform(platformID)
	if err != nil {
		return err
	}

	fmt.Printf("Platform ID: %s\nName: %s\nEndpoint: %s\nAPI Key: %s\nLast Connected: %s\n", platform.PlatformID, platform.Name, platform.Endpoint, platform.APIKey, platform.LastConnected)
	return nil
}
