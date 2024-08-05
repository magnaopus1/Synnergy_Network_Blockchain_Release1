package liquidity

import (
    "errors"
    "math"
    "sync"
    "time"
)

// Trade represents a trade in the market
type Trade struct {
    Pair      string
    Price     float64
    Volume    float64
    Timestamp time.Time
}

// Analytics holds data and methods for analyzing market data
type Analytics struct {
    trades map[string][]Trade
    mu     sync.RWMutex
}

// NewAnalytics creates a new Analytics instance
func NewAnalytics() *Analytics {
    return &Analytics{
        trades: make(map[string][]Trade),
    }
}

// RecordTrade records a trade
func (a *Analytics) RecordTrade(trade Trade) error {
    if trade.Pair == "" || trade.Price <= 0 || trade.Volume <= 0 {
        return errors.New("invalid trade data")
    }

    a.mu.Lock()
    defer a.mu.Unlock()

    a.trades[trade.Pair] = append(a.trades[trade.Pair], trade)
    return nil
}

// GetTrades returns the list of trades for a given trading pair
func (a *Analytics) GetTrades(pair string) ([]Trade, error) {
    a.mu.RLock()
    defer a.mu.RUnlock()

    trades, exists := a.trades[pair]
    if !exists {
        return nil, errors.New("no trades found for the given trading pair")
    }
    return trades, nil
}

// CalculateVWAP calculates the Volume Weighted Average Price for a given trading pair
func (a *Analytics) CalculateVWAP(pair string) (float64, error) {
    trades, err := a.GetTrades(pair)
    if err != nil {
        return 0, err
    }

    var totalVolume, totalPriceVolume float64
    for _, trade := range trades {
        totalVolume += trade.Volume
        totalPriceVolume += trade.Price * trade.Volume
    }

    if totalVolume == 0 {
        return 0, errors.New("total volume is zero")
    }

    return totalPriceVolume / totalVolume, nil
}

// CalculateSMA calculates the Simple Moving Average for a given trading pair over a specified period
func (a *Analytics) CalculateSMA(pair string, period int) (float64, error) {
    trades, err := a.GetTrades(pair)
    if err != nil {
        return 0, err
    }

    if len(trades) < period {
        return 0, errors.New("not enough trades to calculate SMA")
    }

    var sum float64
    for i := len(trades) - period; i < len(trades); i++ {
        sum += trades[i].Price
    }

    return sum / float64(period), nil
}

// CalculateEMA calculates the Exponential Moving Average for a given trading pair over a specified period
func (a *Analytics) CalculateEMA(pair string, period int) (float64, error) {
    trades, err := a.GetTrades(pair)
    if err != nil {
        return 0, err
    }

    if len(trades) < period {
        return 0, errors.New("not enough trades to calculate EMA")
    }

    multiplier := 2 / float64(period+1)
    ema := trades[len(trades)-period].Price

    for i := len(trades) - period + 1; i < len(trades); i++ {
        ema = ((trades[i].Price - ema) * multiplier) + ema
    }

    return ema, nil
}

// CalculateVolatility calculates the volatility for a given trading pair over a specified period
func (a *Analytics) CalculateVolatility(pair string, period int) (float64, error) {
    trades, err := a.GetTrades(pair)
    if err != nil {
        return 0, err
    }

    if len(trades) < period {
        return 0, errors.New("not enough trades to calculate volatility")
    }

    mean, err := a.CalculateSMA(pair, period)
    if err != nil {
        return 0, err
    }

    var variance float64
    for i := len(trades) - period; i < len(trades); i++ {
        variance += math.Pow(trades[i].Price-mean, 2)
    }

    variance /= float64(period)
    return math.Sqrt(variance), nil
}

// DetectAnomalies detects price anomalies based on a threshold
func (a *Analytics) DetectAnomalies(pair string, threshold float64) ([]Trade, error) {
    trades, err := a.GetTrades(pair)
    if err != nil {
        return nil, err
    }

    if len(trades) == 0 {
        return nil, errors.New("no trades available to detect anomalies")
    }

    var anomalies []Trade
    mean, err := a.CalculateSMA(pair, len(trades))
    if err != nil {
        return nil, err
    }

    for _, trade := range trades {
        deviation := math.Abs(trade.Price - mean)
        if deviation > threshold {
            anomalies = append(anomalies, trade)
        }
    }

    return anomalies, nil
}
