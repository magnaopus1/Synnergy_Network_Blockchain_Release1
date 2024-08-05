package factory

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

type TokenFactory struct {
	Tokens map[string]assets.ForexPair
	mutex  sync.Mutex
	Ledger *ledger.ForexTransactionLedger
}

// InitializeTokenFactory initializes the TokenFactory structure
func InitializeTokenFactory() *TokenFactory {
	return &TokenFactory{
		Tokens: make(map[string]assets.ForexPair),
		Ledger: ledger.InitializeForexTransactionLedger(),
	}
}

// IssueToken issues a new Forex token and logs the issuance in the ledger
func (tf *TokenFactory) IssueToken(pairID, baseCurrency, quoteCurrency string, currentRate float64) (string, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	tokenID := fmt.Sprintf("%s-%d", pairID, time.Now().UnixNano())

	if _, exists := tf.Tokens[tokenID]; exists {
		return "", errors.New("token already exists")
	}

	token := assets.ForexPair{
		PairID:        pairID,
		BaseCurrency:  baseCurrency,
		QuoteCurrency: quoteCurrency,
		CurrentRate:   currentRate,
		LastUpdated:   time.Now(),
	}

	tf.Tokens[tokenID] = token

	err := tf.Ledger.LogTransaction(tokenID, "ISSUE", pairID, baseCurrency, quoteCurrency, currentRate)
	if err != nil {
		return "", err
	}

	return tokenID, nil
}

// BurnToken burns a Forex token and logs the burning in the ledger
func (tf *TokenFactory) BurnToken(tokenID string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	token, exists := tf.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	delete(tf.Tokens, tokenID)

	err := tf.Ledger.LogTransaction(tokenID, "BURN", token.PairID, token.BaseCurrency, token.QuoteCurrency, token.CurrentRate)
	if err != nil {
		return err
	}

	return nil
}

// MintToken mints new Forex tokens based on existing pairs
func (tf *TokenFactory) MintToken(pairID string, amount int, baseCurrency, quoteCurrency string, currentRate float64) ([]string, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	tokenIDs := []string{}
	for i := 0; i < amount; i++ {
		tokenID := fmt.Sprintf("%s-%d", pairID, time.Now().UnixNano()+int64(i))

		if _, exists := tf.Tokens[tokenID]; exists {
			return nil, errors.New("token already exists")
		}

		token := assets.ForexPair{
			PairID:        pairID,
			BaseCurrency:  baseCurrency,
			QuoteCurrency: quoteCurrency,
			CurrentRate:   currentRate,
			LastUpdated:   time.Now(),
		}

		tf.Tokens[tokenID] = token
		tokenIDs = append(tokenIDs, tokenID)

		err := tf.Ledger.LogTransaction(tokenID, "MINT", pairID, baseCurrency, quoteCurrency, currentRate)
		if err != nil {
			return nil, err
		}
	}

	return tokenIDs, nil
}

// GetToken retrieves the details of a Forex token
func (tf *TokenFactory) GetToken(tokenID string) (assets.ForexPair, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	token, exists := tf.Tokens[tokenID]
	if !exists {
		return assets.ForexPair{}, errors.New("token not found")
	}

	return token, nil
}

// SaveTokensToFile saves the issued tokens to a file
func (tf *TokenFactory) SaveTokensToFile(filename string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	data, err := json.Marshal(tf.Tokens)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadTokensFromFile loads the issued tokens from a file
func (tf *TokenFactory) LoadTokensFromFile(filename string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &tf.Tokens)
}

// DisplayToken displays the details of a Forex token in a readable format
func (tf *TokenFactory) DisplayToken(tokenID string) error {
	token, err := tf.GetToken(tokenID)
	if err != nil {
		return err
	}

	fmt.Printf("Token ID: %s\nPair ID: %s\nBase Currency: %s\nQuote Currency: %s\nCurrent Rate: %f\nLast Updated: %s\n", tokenID, token.PairID, token.BaseCurrency, token.QuoteCurrency, token.CurrentRate, token.LastUpdated)
	return nil
}
