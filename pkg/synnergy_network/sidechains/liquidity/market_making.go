package liquidity

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// MarketMaker represents an entity that provides liquidity to the market
type MarketMaker struct {
	ID         string
	Assets     map[string]float64
	Liquidity  float64
	Strategies []MarketMakingStrategy
	mu         sync.Mutex
}

// MarketMakingStrategy defines a strategy for market making
type MarketMakingStrategy struct {
	Name   string
	Params map[string]interface{}
	Apply  func(mm *MarketMaker, marketData MarketData) error
}

// MarketData represents the market data needed for making market decisions
type MarketData struct {
	AssetPrices map[string]float64
	OrderBook   OrderBook
}

// OrderBook represents the current state of buy and sell orders in the market
type OrderBook struct {
	BuyOrders  []Order
	SellOrders []Order
}

// Order represents a single buy or sell order
type Order struct {
	Price    float64
	Quantity float64
}

// MarketMakingManager manages multiple market makers
type MarketMakingManager struct {
	mu          sync.RWMutex
	marketMakers map[string]*MarketMaker
}

// NewMarketMakingManager creates a new MarketMakingManager
func NewMarketMakingManager() *MarketMakingManager {
	return &MarketMakingManager{
		marketMakers: make(map[string]*MarketMaker),
	}
}

// AddMarketMaker adds a new market maker
func (mmm *MarketMakingManager) AddMarketMaker(mm *MarketMaker) error {
	mmm.mu.Lock()
	defer mmm.mu.Unlock()

	if _, exists := mmm.marketMakers[mm.ID]; exists {
		return errors.New("market maker already exists")
	}

	mmm.marketMakers[mm.ID] = mm
	return nil
}

// GetMarketMaker retrieves a market maker by ID
func (mmm *MarketMakingManager) GetMarketMaker(id string) (*MarketMaker, error) {
	mmm.mu.RLock()
	defer mmm.mu.RUnlock()

	mm, exists := mmm.marketMakers[id]
	if !exists {
		return nil, errors.New("market maker not found")
	}

	return mm, nil
}

// ListMarketMakers lists all market makers
func (mmm *MarketMakingManager) ListMarketMakers() map[string]*MarketMaker {
	mmm.mu.RLock()
	defer mmm.mu.RUnlock()

	marketMakers := make(map[string]*MarketMaker)
	for id, mm := range mmm.marketMmakers {
		marketMakers[id] = mm
	}

	return marketMakers
}

// RemoveMarketMaker removes a market maker by ID
func (mmm *MarketMakingManager) RemoveMarketMaker(id string) error {
	mmm.mu.Lock()
	defer mmm.mu.Unlock()

	if _, exists := mmm.marketMakers[id]; !exists {
		return errors.New("market maker not found")
	}

	delete(mmm.marketMakers, id)
	return nil
}

// UpdateMarketMaker updates an existing market maker
func (mmm *MarketMakingManager) UpdateMarketMaker(mm *MarketMaker) error {
	mmm.mu.Lock()
	defer mmm.mu.Unlock()

	if _, exists := mmm.marketMakers[mm.ID]; !exists {
		return errors.New("market maker not found")
	}

	mmm.marketMmakers[mm.ID] = mm
	return nil
}

// ApplyStrategy applies a market making strategy to a market maker
func (mm *MarketMaker) ApplyStrategy(strategy MarketMakingStrategy, marketData MarketData) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	return strategy.Apply(mm, marketData)
}

// ExampleStrategy is an example of a market making strategy
func ExampleStrategy(mm *MarketMaker, marketData MarketData) error {
	for asset, price := range marketData.AssetPrices {
		quantity := mm.Liquidity / price
		order := Order{
			Price:    price,
			Quantity: quantity,
		}
		marketData.OrderBook.BuyOrders = append(marketData.OrderBook.BuyOrders, order)
		mm.Liquidity -= quantity * price
	}
	return nil
}

// StartMarketMaking starts the market making process
func (mmm *MarketMakingManager) StartMarketMaking(marketData MarketData, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mmm.mu.RLock()
			for _, mm := range mmm.marketMakers {
				for _, strategy := range mm.Strategies {
					err := mm.ApplyStrategy(strategy, marketData)
					if err != nil {
						fmt.Printf("Error applying strategy %s: %v\n", strategy.Name, err)
					}
				}
			}
			mmm.mu.RUnlock()
		}
	}
}

// GenerateRandomMarketData generates random market data for testing
func GenerateRandomMarketData() MarketData {
	return MarketData{
		AssetPrices: map[string]float64{
			"BTC":  50000 + rand.Float64()*1000,
			"ETH":  4000 + rand.Float64()*100,
			"USDT": 1 + rand.Float64()*0.01,
		},
		OrderBook: OrderBook{
			BuyOrders:  []Order{},
			SellOrders: []Order{},
		},
	}
}
