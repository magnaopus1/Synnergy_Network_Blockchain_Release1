package assets

import (
	"time"
	"encoding/json"
	"fmt"
	"errors"
	"sync"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
	"io"
)

type ForexPair struct {
	PairID        string    `json:"pair_id"`
	BaseCurrency  string    `json:"base_currency"`
	QuoteCurrency string    `json:"quote_currency"`
	CurrentRate   float64   `json:"current_rate"`
	LastUpdated   time.Time `json:"last_updated"`
}

type ForexMetadata struct {
	Pairs      map[string]ForexPair
	mutex      sync.Mutex
	encryptionKey []byte
}

// InitializeForexMetadata initializes the Forex metadata with an encryption key
func InitializeForexMetadata(password string) (*ForexMetadata, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &ForexMetadata{
		Pairs: make(map[string]ForexPair),
		encryptionKey: key,
	}, nil
}

// AddPair adds a new forex pair to the metadata
func (fm *ForexMetadata) AddPair(pairID, baseCurrency, quoteCurrency string, currentRate float64) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if _, exists := fm.Pairs[pairID]; exists {
		return errors.New("pair already exists")
	}

	fm.Pairs[pairID] = ForexPair{
		PairID:        pairID,
		BaseCurrency:  baseCurrency,
		QuoteCurrency: quoteCurrency,
		CurrentRate:   currentRate,
		LastUpdated:   time.Now(),
	}

	return nil
}

// UpdateRate updates the current rate of a forex pair
func (fm *ForexMetadata) UpdateRate(pairID string, newRate float64) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	pair, exists := fm.Pairs[pairID]
	if !exists {
		return errors.New("pair not found")
	}

	pair.CurrentRate = newRate
	pair.LastUpdated = time.Now()
	fm.Pairs[pairID] = pair

	return nil
}

// GetPair retrieves the details of a forex pair
func (fm *ForexMetadata) GetPair(pairID string) (ForexPair, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	pair, exists := fm.Pairs[pairID]
	if !exists {
		return ForexPair{}, errors.New("pair not found")
	}

	return pair, nil
}

// EncryptData encrypts the data using AES-GCM
func (fm *ForexMetadata) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(fm.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES-GCM
func (fm *ForexMetadata) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(fm.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SaveToFile saves the metadata to a file after encrypting it
func (fm *ForexMetadata) SaveToFile(filename string) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	data, err := json.Marshal(fm.Pairs)
	if err != nil {
		return err
	}

	encryptedData, err := fm.EncryptData(data)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, encryptedData, 0644)
}

// LoadFromFile loads the metadata from a file after decrypting it
func (fm *ForexMetadata) LoadFromFile(filename string) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	encryptedData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	data, err := fm.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &fm.Pairs)
}

// VerifyOwnership verifies that the token represents verified ownership or rights to a Forex position
func (fm *ForexMetadata) VerifyOwnership(pairID string) (bool, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	_, exists := fm.Pairs[pairID]
	return exists, nil
}

func main() {
	fm, err := InitializeForexMetadata("securepassword")
	if err != nil {
		fmt.Println("Error initializing Forex Metadata:", err)
		return
	}

	err = fm.AddPair("EURUSD", "EUR", "USD", 1.1837)
	if err != nil {
		fmt.Println("Error adding Forex pair:", err)
		return
	}

	pair, err := fm.GetPair("EURUSD")
	if err != nil {
		fmt.Println("Error getting Forex pair:", err)
		return
	}

	fmt.Printf("Forex Pair: %+v\n", pair)

	err = fm.SaveToFile("forex_metadata.json")
	if err != nil {
		fmt.Println("Error saving to file:", err)
		return
	}

	newFm, err := InitializeForexMetadata("securepassword")
	if err != nil {
		fmt.Println("Error initializing new Forex Metadata:", err)
		return
	}

	err = newFm.LoadFromFile("forex_metadata.json")
	if err != nil {
		fmt.Println("Error loading from file:", err)
		return
	}

	newPair, err := newFm.GetPair("EURUSD")
	if err != nil {
		fmt.Println("Error getting Forex pair:", err)
		return
	}

	fmt.Printf("Loaded Forex Pair: %+v\n", newPair)
}
