package currency_representation

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// ExchangeRateProvider defines the interface for exchange rate providers
type ExchangeRateProvider interface {
	GetExchangeRate(currencyCode string) (float64, error)
}

// ExchangeRateManager manages the exchange rates for different currencies
type ExchangeRateManager struct {
	provider    ExchangeRateProvider
	rates       map[string]float64
	mu          sync.RWMutex
	updateFreq  time.Duration
	notifyChans map[string][]chan float64
}

// NewExchangeRateManager initializes a new ExchangeRateManager
func NewExchangeRateManager(provider ExchangeRateProvider, updateFreq time.Duration) *ExchangeRateManager {
	erm := &ExchangeRateManager{
		provider:    provider,
		rates:       make(map[string]float64),
		updateFreq:  updateFreq,
		notifyChans: make(map[string][]chan float64),
	}

	go erm.startUpdatingRates()
	return erm
}

// startUpdatingRates periodically updates the exchange rates
func (erm *ExchangeRateManager) startUpdatingRates() {
	ticker := time.NewTicker(erm.updateFreq)
	for {
		<-ticker.C
		erm.updateRates()
	}
}

// updateRates updates the exchange rates from the provider
func (erm *ExchangeRateManager) updateRates() {
	erm.mu.Lock()
	defer erm.mu.Unlock()

	for currencyCode := range erm.rates {
		rate, err := erm.provider.GetExchangeRate(currencyCode)
		if err == nil {
			erm.rates[currencyCode] = rate
			erm.notifySubscribers(currencyCode, rate)
		}
	}
}

// notifySubscribers notifies subscribers about the updated exchange rate
func (erm *ExchangeRateManager) notifySubscribers(currencyCode string, rate float64) {
	if chans, exists := erm.notifyChans[currencyCode]; exists {
		for _, ch := range chans {
			ch <- rate
		}
	}
}

// AddCurrency adds a new currency to the manager
func (erm *ExchangeRateManager) AddCurrency(currencyCode string) error {
	erm.mu.Lock()
	defer erm.mu.Unlock()

	if _, exists := erm.rates[currencyCode]; exists {
		return errors.New("currency already exists")
	}

	rate, err := erm.provider.GetExchangeRate(currencyCode)
	if err != nil {
		return err
	}

	erm.rates[currencyCode] = rate
	return nil
}

// GetExchangeRate retrieves the exchange rate for a given currency
func (erm *ExchangeRateManager) GetExchangeRate(currencyCode string) (float64, error) {
	erm.mu.RLock()
	defer erm.mu.RUnlock()

	rate, exists := erm.rates[currencyCode]
	if !exists {
		return 0, errors.New("currency not found")
	}

	return rate, nil
}

// SubscribeExchangeRateChanges subscribes to exchange rate updates for a given currency
func (erm *ExchangeRateManager) SubscribeExchangeRateChanges(currencyCode string) (chan float64, error) {
	erm.mu.Lock()
	defer erm.mu.Unlock()

	if _, exists := erm.rates[currencyCode]; !exists {
		return nil, errors.New("currency not found")
	}

	ch := make(chan float64, 1)
	erm.notifyChans[currencyCode] = append(erm.notifyChans[currencyCode], ch)
	return ch, nil
}

// UnsubscribeExchangeRateChanges unsubscribes from exchange rate updates for a given currency
func (erm *ExchangeRateManager) UnsubscribeExchangeRateChanges(currencyCode string, ch chan float64) error {
	erm.mu.Lock()
	defer erm.mu.Unlock()

	if chans, exists := erm.notifyChans[currencyCode]; exists {
		for i, c := range chans {
			if c == ch {
				erm.notifyChans[currencyCode] = append(chans[:i], chans[i+1:]...)
				close(ch)
				return nil
			}
		}
	}

	return errors.New("subscription not found")
}

// APIExchangeRateProvider is an implementation of ExchangeRateProvider using an external API
type APIExchangeRateProvider struct {
	apiURL string
}

// NewAPIExchangeRateProvider initializes a new APIExchangeRateProvider
func NewAPIExchangeRateProvider(apiURL string) *APIExchangeRateProvider {
	return &APIExchangeRateProvider{apiURL: apiURL}
}

// GetExchangeRate retrieves the exchange rate for a given currency from the API
func (aep *APIExchangeRateProvider) GetExchangeRate(currencyCode string) (float64, error) {
	resp, err := http.Get(aep.apiURL + "/rate?currency=" + currencyCode)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("failed to get exchange rate")
	}

	var result struct {
		Rate float64 `json:"rate"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	return result.Rate, nil
}
