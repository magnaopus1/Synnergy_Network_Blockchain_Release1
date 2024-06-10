package syn3400

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// ForexPair represents a currency pair in the Forex market.
type ForexPair struct {
    PairID     string  `json:"pairId"`
    BaseCurrency   string  `json:"baseCurrency"`
    QuoteCurrency  string  `json:"quoteCurrency"`
    CurrentRate    float64 `json:"currentRate"`
    LastUpdated    time.Time `json:"lastUpdated"`
}

// ForexToken represents a speculative position in a ForexPair, encapsulating the trade details.
type ForexToken struct {
    TokenID         string    `json:"tokenId"`
    ForexPair       ForexPair `json:"forexPair"`
    Holder          string    `json:"holder"`
    PositionSize    float64   `json:"positionSize"` // The size of the position in base currency.
    OpenRate        float64   `json:"openRate"`     // The rate at which the position was opened.
    IsLongPosition  bool      `json:"isLongPosition"`  // True if long position, false if short.
    OpenedDate      time.Time `json:"openedDate"`
}

// ForexRegistry manages the lifecycle of forex tokens and currency pairs.
type ForexRegistry struct {
    ForexPairs map[string]*ForexPair
    Tokens     map[string]*ForexToken
    mutex      sync.Mutex
}

// NewForexRegistry creates a new ForexRegistry instance.
func NewForexRegistry() *ForexRegistry {
    return &ForexRegistry{
        ForexPairs: make(map[string]*ForexPair),
        Tokens:     make(map[string]*ForexToken),
    }
}

// AddForexPair adds a new currency pair to the registry.
func (r *ForexRegistry) AddForexPair(pairId, baseCurrency, quoteCurrency string, initialRate float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    if _, exists := r.ForexPairs[pairId]; exists {
        return errors.New("currency pair already exists")
    }

    pair := &ForexPair{
        PairID: pairId,
        BaseCurrency: baseCurrency,
        QuoteCurrency: quoteCurrency,
        CurrentRate: initialRate,
        LastUpdated: time.Now(),
    }

    r.ForexPairs[pairId] = pair
    return nil
}

// OpenPosition opens a new position in a ForexPair and creates a token.
func (r *ForexRegistry) OpenPosition(pairId, holder string, size float64, isLong bool, openRate float64) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    pair, exists := r.ForexPairs[pairId]
    if !exists {
        return "", fmt.Errorf("currency pair not found: %s", pairId)
    }

    tokenID := fmt.Sprintf("%s-%s-%d", pairId, holder, time.Now().UnixNano())
    forexToken := &ForexToken{
        TokenID:        tokenID,
        ForexPair:      *pair,
        Holder:         holder,
        PositionSize:   size,
        OpenRate:       openRate,
        IsLongPosition: isLong,
        OpenedDate:     time.Now(),
    }

    r.Tokens[tokenID] = forexToken
    return tokenID, nil
}

// ClosePosition closes an existing position and removes the associated token.
func (r *ForexRegistry) ClosePosition(tokenID string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    if _, exists := r.Tokens[tokenID]; !exists {
        return errors.New("forex token not found")
    }

    delete(r.Tokens, tokenID)
    return nil
}

// UpdateForexPairRate updates the exchange rate for a currency pair.
func (r *ForexRegistry) UpdateForexPairRate(pairId string, newRate float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    pair, exists := r.ForexPairs[pairId]
    if !exists {
        return errors.New("currency pair not found")
    }

    pair.CurrentRate = newRate
    pair.LastUpdated = time.Now()
    return nil
}
