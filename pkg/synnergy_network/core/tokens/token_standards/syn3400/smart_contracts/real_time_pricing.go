package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RealTimePricing represents the structure for real-time Forex pricing.
type RealTimePricing struct {
	PairID         string    `json:"pair_id"`
	BaseCurrency   string    `json:"base_currency"`
	QuoteCurrency  string    `json:"quote_currency"`
	CurrentRate    float64   `json:"current_rate"`
	LastUpdated    time.Time `json:"last_updated"`
	Provider       string    `json:"provider"`
}

// RealTimePricingManager manages real-time Forex pricing updates and subscriptions.
type RealTimePricingManager struct {
	PricingData   map[string]*RealTimePricing
	Subscribers   map[string][]chan RealTimePricing
	ProviderURL   string
	ProviderAPIKey string
	mutex         sync.Mutex
}

// NewRealTimePricingManager initializes the RealTimePricingManager.
func NewRealTimePricingManager(providerURL, providerAPIKey string) *RealTimePricingManager {
	return &RealTimePricingManager{
		PricingData:   make(map[string]*RealTimePricing),
		Subscribers:   make(map[string][]chan RealTimePricing),
		ProviderURL:   providerURL,
		ProviderAPIKey: providerAPIKey,
	}
}

// Subscribe adds a subscriber for real-time pricing updates.
func (rtpm *RealTimePricingManager) Subscribe(pairID string, ch chan RealTimePricing) {
	rtpm.mutex.Lock()
	defer rtpm.mutex.Unlock()

	if _, exists := rtpm.Subscribers[pairID]; !exists {
		rtpm.Subscribers[pairID] = []chan RealTimePricing{}
	}
	rtpm.Subscribers[pairID] = append(rtpm.Subscribers[pairID], ch)
}

// Unsubscribe removes a subscriber from real-time pricing updates.
func (rtpm *RealTimePricingManager) Unsubscribe(pairID string, ch chan RealTimePricing) {
	rtpm.mutex.Lock()
	defer rtpm.mutex.Unlock()

	if subscribers, exists := rtpm.Subscribers[pairID]; exists {
		for i, subscriber := range subscribers {
			if subscriber == ch {
				rtpm.Subscribers[pairID] = append(subscribers[:i], subscribers[i+1:]...)
				break
			}
		}
	}
}

// UpdatePricingData updates the pricing data for a given Forex pair.
func (rtpm *RealTimePricingManager) UpdatePricingData(pairID, baseCurrency, quoteCurrency string, rate float64, provider string) {
	rtpm.mutex.Lock()
	defer rtpm.mutex.Unlock()

	pricing := &RealTimePricing{
		PairID:         pairID,
		BaseCurrency:   baseCurrency,
		QuoteCurrency:  quoteCurrency,
		CurrentRate:    rate,
		LastUpdated:    time.Now(),
		Provider:       provider,
	}
	rtpm.PricingData[pairID] = pricing

	rtpm.notifySubscribers(pairID, *pricing)
}

// GetPricingData retrieves the current pricing data for a given Forex pair.
func (rtpm *RealTimePricingManager) GetPricingData(pairID string) (*RealTimePricing, error) {
	rtpm.mutex.Lock()
	defer rtpm.mutex.Unlock()

	pricing, exists := rtpm.PricingData[pairID]
	if !exists {
		return nil, errors.New("pricing data not found")
	}

	return pricing, nil
}

// FetchPricingFromProvider fetches pricing data from the external provider.
func (rtpm *RealTimePricingManager) FetchPricingFromProvider(pairID string) error {
	url := fmt.Sprintf("%s?pair=%s&apikey=%s", rtpm.ProviderURL, pairID, rtpm.ProviderAPIKey)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch pricing data: %s", resp.Status)
	}

	var pricing RealTimePricing
	if err := json.NewDecoder(resp.Body).Decode(&pricing); err != nil {
		return err
	}

	rtpm.UpdatePricingData(pricing.PairID, pricing.BaseCurrency, pricing.QuoteCurrency, pricing.CurrentRate, pricing.Provider)
	return nil
}

// notifySubscribers notifies all subscribers of pricing updates for a given Forex pair.
func (rtpm *RealTimePricingManager) notifySubscribers(pairID string, pricing RealTimePricing) {
	if subscribers, exists := rtpm.Subscribers[pairID]; exists {
		for _, subscriber := range subscribers {
			go func(ch chan RealTimePricing) {
				ch <- pricing
			}(subscriber)
		}
	}
}

// EvaluatePricing ensures the current pricing data is accurate and up-to-date.
func (rtpm *RealTimePricingManager) EvaluatePricing(pairID string) (bool, error) {
	rtpm.mutex.Lock()
	defer rtpm.mutex.Unlock()

	pricing, exists := rtpm.PricingData[pairID]
	if !exists {
		return false, errors.New("pricing data not found")
	}

	if time.Since(pricing.LastUpdated) > time.Minute*5 {
		return false, errors.New("pricing data is outdated")
	}

	// Additional evaluation logic can be added here.
	return true, nil
}

// LogPricingEvent logs events related to real-time pricing updates.
func (rtpm *RealTimePricingManager) LogPricingEvent(pricing *RealTimePricing, eventType string) {
	event := map[string]interface{}{
		"event_type":   eventType,
		"pair_id":      pricing.PairID,
		"base_currency": pricing.BaseCurrency,
		"quote_currency": pricing.QuoteCurrency,
		"current_rate":  pricing.CurrentRate,
		"timestamp":    time.Now().UTC(),
		"provider":     pricing.Provider,
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}

// generateUniqueID generates a unique identifier (dummy implementation).
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
