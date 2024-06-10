package syn3300

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// MarketDataFetcher is an interface for fetching current market data for ETFs.
type MarketDataFetcher interface {
    FetchCurrentPrice(etfID string) (float64, error)
}

// ETF represents the structure of an exchange-traded fund on the blockchain.
type ETF struct {
    ETFID           string    `json:"etfId"`
    Name            string    `json:"name"`
    TotalShares     float64   `json:"totalShares"`
    AvailableShares float64   `json:"availableShares"`
    CurrentPrice    float64   `json:"currentPrice"`
}

// ETFShareToken represents a fraction of an ETF, allowing for partial ownership.
type ETFShareToken struct {
    TokenID        string    `json:"tokenId"`
    ETF            ETF       `json:"etf"`
    Holder         string    `json:"holder"`
    Shares         float64   `json:"shares"` // Amount of shares this token represents.
    IssuedDate     time.Time `json:"issuedDate"`
    LastUpdateDate time.Time `json:"lastUpdateDate"`
}

// ETFRegistry manages the lifecycle of ETFs and their tokens.
type ETFRegistry struct {
    ETFs   map[string]*ETF
    Tokens map[string]*ETFShareToken
    mutex  sync.Mutex
    dataFetcher MarketDataFetcher
}

// NewETFRegistry initializes a new ETFRegistry with a market data fetcher.
func NewETFRegistry(fetcher MarketDataFetcher) *ETFRegistry {
    return &ETFRegistry{
        ETFs: make(map[string]*ETF),
        Tokens: make(map[string]*ETFShareToken),
        dataFetcher: fetcher,
    }
}

// CreateETF initializes a new ETF in the registry.
func (r *ETFRegistry) CreateETF(etfId, name string, totalShares float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    if _, exists := r.ETFs[etfId]; exists {
        return errors.New("ETF already exists")
    }

    // Fetch the current market price for the ETF.
    price, err := r.dataFetcher.FetchCurrentPrice(etfId)
    if err != nil {
        return fmt.Errorf("error fetching market price: %v", err)
    }

    etf := &ETF{
        ETFID: etfId,
        Name: name,
        TotalShares: totalShares,
        AvailableShares: totalShares,
        CurrentPrice: price,
    }
    r.ETFs[etfId] = etf
    return nil
}

// IssueShareToken issues new ETF share tokens to a holder.
func (r *ETFRegistry) IssueShareToken(etfId, holder string, shares float64) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    etf, exists := r.ETFs[etfId]
    if !exists {
        return "", errors.New("ETF not found")
    }
    if etf.AvailableShares < shares {
        return "", fmt.Errorf("not enough available shares in ETF to issue: %s", etf.Name)
    }

    tokenID := fmt.Sprintf("%s-%s-%d", etfId, holder, time.Now().UnixNano()) // Unique token ID
    etf.AvailableShares -= shares
    etfShareToken := &ETFShareToken{
        TokenID: tokenID,
        ETF: *etf,
        Holder: holder,
        Shares: shares,
        IssuedDate: time.Now(),
        LastUpdateDate: time.Now(),
    }

    r.Tokens[tokenID] = etfShareToken
    return tokenID, nil
}

// UpdateTokenPrice updates the token value based on the current ETF price.
func (r *ETFRegistry) UpdateTokenPrice(tokenID string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("ETF share token not found")
    }

    currentPrice, err := r.dataFetcher.FetchCurrentPrice(token.ETF.ETFID)
    if err != nil {
        return fmt.Errorf("error fetching market price: %v", err)
    }

    token.ETF.CurrentPrice = currentPrice
    token.LastUpdateDate = time.Now()
    return nil
}

// TransferShares transfers shares from one holder to another.
func (r *ETFRegistry) TransferShares(tokenID, newHolder string, shares float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("ETF share token not found")
    }
    if shares > token.Shares {
        return errors.New("insufficient shares to transfer")
    }

    // Create new token for new holder with specified number of shares
    newTokenID := fmt.Sprintf("%s-%s-%d", token.ETF.ETFID, newHolder, time.Now().UnixNano())
    newToken := &ETFShareToken{
        TokenID: newTokenID,
        ETF: token.ETF,
        Holder: newHolder,
        Shares: shares,
        IssuedDate: time.Now(),
        LastUpdateDate: time.Now(),
    }
    r.Tokens[newTokenID] = newToken

    // Update original token
    token.Shares -= shares
    if token.Shares == 0 {
        delete(r.Tokens, tokenID)
    } else {
        r.Tokens[tokenID] = token
    }

    return nil
}

// ListTokensByHolder lists all tokens held by a specific holder.
func (r *ETFRegistry) ListTokensByHolder(holder string) []ETFShareToken {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    var tokens []ETFShareToken
    for _, token := range r.Tokens {
        if token.Holder == holder {
            tokens = append(tokens, *token)
        }
    }
    return tokens
}
