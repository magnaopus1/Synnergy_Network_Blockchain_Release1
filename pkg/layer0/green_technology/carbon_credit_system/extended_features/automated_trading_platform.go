package extended_features

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// CarbonCreditToken represents a carbon credit token.
type CarbonCreditToken struct {
	ID        string
	Owner     string
	Amount    float64
	IssuedAt  time.Time
	ExpiresAt time.Time
	IsRetired bool
}

// NewCarbonCreditToken creates a new carbon credit token.
func NewCarbonCreditToken(owner string, amount float64, expiresAt time.Time) (*CarbonCreditToken, error) {
	id, err := generateUniqueID()
	if err != nil {
		return nil, err
	}
	token := &CarbonCreditToken{
		ID:        id,
		Owner:     owner,
		Amount:    amount,
		IssuedAt:  time.Now(),
		ExpiresAt: expiresAt,
		IsRetired: false,
	}
	return token, nil
}

// generateUniqueID generates a unique identifier.
func generateUniqueID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// AutomatedTradingPlatform represents the platform for automated carbon credit trading.
type AutomatedTradingPlatform struct {
	tokens          map[string]*CarbonCreditToken
	tradeQueue      []*TradeRequest
	marketPrice     float64
	dataFeedChannel chan MarketData
}

// TradeRequest represents a request to trade carbon credits.
type TradeRequest struct {
	TokenID string
	Buyer   string
	Amount  float64
	Price   float64
}

// MarketData represents real-time market data.
type MarketData struct {
	Supply int
	Demand int
	Price  float64
}

// NewAutomatedTradingPlatform creates a new automated trading platform.
func NewAutomatedTradingPlatform() *AutomatedTradingPlatform {
	return &AutomatedTradingPlatform{
		tokens:          make(map[string]*CarbonCreditToken),
		tradeQueue:      []*TradeRequest{},
		marketPrice:     0.0,
		dataFeedChannel: make(chan MarketData),
	}
}

// AddToken adds a new token to the platform.
func (platform *AutomatedTradingPlatform) AddToken(token *CarbonCreditToken) {
	platform.tokens[token.ID] = token
}

// RequestTrade creates a trade request.
func (platform *AutomatedTradingPlatform) RequestTrade(tokenID, buyer string, amount, price float64) error {
	token, exists := platform.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	if token.IsRetired {
		return errors.New("token is retired")
	}
	if amount > token.Amount {
		return errors.New("insufficient token amount")
	}
	tradeRequest := &TradeRequest{
		TokenID: tokenID,
		Buyer:   buyer,
		Amount:  amount,
		Price:   price,
	}
	platform.tradeQueue = append(platform.tradeQueue, tradeRequest)
	return nil
}

// ProcessTrades processes the trade requests.
func (platform *AutomatedTradingPlatform) ProcessTrades() {
	for _, trade := range platform.tradeQueue {
		token := platform.tokens[trade.TokenID]
		if trade.Price >= platform.marketPrice {
			platform.executeTrade(token, trade)
		}
	}
	platform.tradeQueue = []*TradeRequest{}
}

// executeTrade executes a trade.
func (platform *AutomatedTradingPlatform) executeTrade(token *CarbonCreditToken, trade *TradeRequest) {
	token.Amount -= trade.Amount
	if token.Amount == 0 {
		token.IsRetired = true
	}
	newToken, _ := NewCarbonCreditToken(trade.Buyer, trade.Amount, token.ExpiresAt)
	platform.AddToken(newToken)
	fmt.Printf("Trade executed: %s -> %s, Amount: %f, Price: %f\n", token.Owner, trade.Buyer, trade.Amount, trade.Price)
}

// UpdateMarketPrice updates the market price based on real-time data.
func (platform *AutomatedTradingPlatform) UpdateMarketPrice() {
	for data := range platform.dataFeedChannel {
		platform.marketPrice = calculateMarketPrice(data)
	}
}

// calculateMarketPrice calculates the market price based on supply and demand.
func calculateMarketPrice(data MarketData) float64 {
	if data.Demand == 0 {
		return 0
	}
	return float64(data.Supply) / float64(data.Demand) * data.Price
}

// FeedMarketData feeds real-time market data into the platform.
func (platform *AutomatedTradingPlatform) FeedMarketData(data MarketData) {
	platform.dataFeedChannel <- data
}

// MonitorIoTData monitors IoT devices for emission data and updates the platform.
func (platform *AutomatedTradingPlatform) MonitorIoTData(deviceChannel chan IoTDeviceData) {
	for data := range deviceChannel {
		token, exists := platform.tokens[data.TokenID]
		if exists && !token.IsRetired {
			token.Amount -= data.EmissionAmount
			if token.Amount <= 0 {
				token.IsRetired = true
			}
			fmt.Printf("IoT data processed: TokenID: %s, EmissionAmount: %f\n", data.TokenID, data.EmissionAmount)
		}
	}
}

// IoTDeviceData represents data from IoT devices.
type IoTDeviceData struct {
	TokenID        string
	EmissionAmount float64
}

func main() {
	platform := NewAutomatedTradingPlatform()

	// Example usage
	token, _ := NewCarbonCreditToken("Alice", 100, time.Now().Add(24*time.Hour))
	platform.AddToken(token)

	platform.RequestTrade(token.ID, "Bob", 50, 10)
	platform.ProcessTrades()

	data := MarketData{Supply: 100, Demand: 50, Price: 5}
	platform.FeedMarketData(data)

	go platform.UpdateMarketPrice()

	iotChannel := make(chan IoTDeviceData)
	go platform.MonitorIoTData(iotChannel)

	iotChannel <- IoTDeviceData{TokenID: token.ID, EmissionAmount: 10}
	close(iotChannel)
}
