package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
)

// ExternalAPIIntegration handles integration with external APIs for blockchain operations.
type ExternalAPIIntegration struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
	Address    string
	APIs       map[string]*APIConfig
	mutex      sync.RWMutex
}

// APIConfig stores the configuration for an external API.
type APIConfig struct {
	Name    string
	BaseURL string
	APIKey  string
}

// NewExternalAPIIntegration generates a new ExternalAPIIntegration instance.
func NewExternalAPIIntegration() (*ExternalAPIIntegration, error) {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := privateKey.PublicKey
	address := crypto.PubkeyToAddress(publicKey).Hex()

	return &ExternalAPIIntegration{
		privateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
		APIs:       make(map[string]*APIConfig),
	}, nil
}

// AddAPI adds a new external API configuration.
func (e *ExternalAPIIntegration) AddAPI(name, baseURL, apiKey string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if _, exists := e.APIs[name]; exists {
		return fmt.Errorf("API %s already exists", name)
	}

	e.APIs[name] = &APIConfig{
		Name:    name,
		BaseURL: baseURL,
		APIKey:  apiKey,
	}

	return nil
}

// RemoveAPI removes an existing external API configuration.
func (e *ExternalAPIIntegration) RemoveAPI(name string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if _, exists := e.APIs[name]; !exists {
		return fmt.Errorf("API %s not found", name)
	}

	delete(e.APIs, name)
	return nil
}

// FetchBalance fetches the balance from an external API.
func (e *ExternalAPIIntegration) FetchBalance(apiName, address string) (*big.Int, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	apiConfig, exists := e.APIs[apiName]
	if !exists {
		return nil, fmt.Errorf("API %s not found", apiName)
	}

	url := fmt.Sprintf("%s/balance/%s", apiConfig.BaseURL, address)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiConfig.APIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch balance: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch balance: status code %d", resp.StatusCode)
	}

	var result struct {
		Balance string `json:"balance"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	balance, ok := new(big.Int).SetString(result.Balance, 10)
	if !ok {
		return nil, fmt.Errorf("invalid balance format")
	}

	return balance, nil
}

// SendTransaction sends a transaction through an external API.
func (e *ExternalAPIIntegration) SendTransaction(apiName string, to string, amount *big.Int) (string, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	apiConfig, exists := e.APIs[apiName]
	if !exists {
		return "", fmt.Errorf("API %s not found", apiName)
	}

	txData := map[string]string{
		"from":   e.Address,
		"to":     to,
		"amount": amount.String(),
	}
	data, err := json.Marshal(txData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal transaction data: %v", err)
	}

	url := fmt.Sprintf("%s/transaction", apiConfig.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiConfig.APIKey))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to send transaction: status code %d, response %s", resp.StatusCode, string(body))
	}

	var result struct {
		TxHash string `json:"txHash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	return result.TxHash, nil
}

// SignMessage signs a message with the wallet's private key.
func (e *ExternalAPIIntegration) SignMessage(message []byte) ([]byte, error) {
	hash := crypto.Keccak256Hash(message)
	signature, err := crypto.Sign(hash.Bytes(), e.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %v", err)
	}

	return signature, nil
}

// VerifyMessage verifies a signed message.
func (e *ExternalAPIIntegration) VerifyMessage(message, signature []byte) (bool, error) {
	hash := crypto.Keccak256Hash(message)
	pubKey, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %v", err)
	}

	return pubKey.Equal(e.PublicKey), nil
}

// main function for demonstration purposes.
func main() {
	wallet, err := NewExternalAPIIntegration()
	if err != nil {
		fmt.Println("Error creating wallet:", err)
		return
	}

	fmt.Println("New wallet address:", wallet.Address)

	err = wallet.AddAPI("ExampleAPI", "https://api.example.com", "example-api-key")
	if err != nil {
		fmt.Println("Error adding API:", err)
		return
	}

	balance, err := wallet.FetchBalance("ExampleAPI", wallet.Address)
	if err != nil {
		fmt.Println("Error fetching balance:", err)
		return
	}
	fmt.Println("Fetched balance:", balance)

	txHash, err := wallet.SendTransaction("ExampleAPI", "0xRecipientAddress", big.NewInt(100))
	if err != nil {
		fmt.Println("Error sending transaction:", err)
		return
	}
	fmt.Println("Transaction sent, hash:", txHash)

	message := []byte("Hello, Synnergy Network!")
	signature, err := wallet.SignMessage(message)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	fmt.Println("Message signed:", signature)

	valid, err := wallet.VerifyMessage(message, signature)
	if err != nil {
		fmt.Println("Error verifying message:", err)
		return
	}
	fmt.Println("Message verification result:", valid)
}
