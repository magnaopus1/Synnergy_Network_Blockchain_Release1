package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// APIClientConfig contains the configuration for API clients
type APIClientConfig struct {
	BaseURL       string
	APIKey        string
	Timeout       time.Duration
	RetryAttempts int
}

// APIClient handles API connectivity for the SYN3300 token standard
type APIClient struct {
	config            APIClientConfig
	encryptionService *encryption.EncryptionService
	ledgerService     *ledger.LedgerService
	client            *http.Client
}

// NewAPIClient creates a new instance of APIClient
func NewAPIClient(config APIClientConfig, encryptionService *encryption.EncryptionService, ledgerService *ledger.LedgerService) *APIClient {
	return &APIClient{
		config:            config,
		encryptionService: encryptionService,
		ledgerService:     ledgerService,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// SendRequest sends an HTTP request to the configured API
func (api *APIClient) SendRequest(method, endpoint string, payload interface{}) ([]byte, error) {
	url := api.config.BaseURL + endpoint

	var body []byte
	var err error

	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+api.config.APIKey)

	for i := 0; i < api.config.RetryAttempts; i++ {
		resp, err := api.client.Do(req)
		if err != nil {
			if i == api.config.RetryAttempts-1 {
				return nil, err
			}
			time.Sleep(2 * time.Second)
			continue
		}

		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("received non-OK response: " + resp.Status)
		}

		responseData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return responseData, nil
	}

	return nil, errors.New("failed to send request after retries")
}

// FetchETFData fetches ETF data from the external API
func (api *APIClient) FetchETFData(etfID string) (map[string]interface{}, error) {
	endpoint := "/etf/data/" + etfID
	response, err := api.SendRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var etfData map[string]interface{}
	if err := json.Unmarshal(response, &etfData); err != nil {
		return nil, err
	}

	return etfData, nil
}

// PostTransaction posts a transaction to the external API for recording purposes
func (api *APIClient) PostTransaction(transactionData map[string]interface{}) (string, error) {
	endpoint := "/transactions"
	response, err := api.SendRequest(http.MethodPost, endpoint, transactionData)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(response, &result); err != nil {
		return "", err
	}

	transactionID, ok := result["transaction_id"].(string)
	if !ok {
		return "", errors.New("failed to retrieve transaction ID from response")
	}

	return transactionID, nil
}

// EncryptAndStoreData encrypts and stores data using the ledger service
func (api *APIClient) EncryptAndStoreData(data interface{}) (string, error) {
	encryptedData, err := api.encryptionService.EncryptData(data)
	if err != nil {
		return "", err
	}

	recordID, err := api.ledgerService.RecordData(encryptedData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// DecryptAndRetrieveData retrieves and decrypts data using the ledger service
func (api *APIClient) DecryptAndRetrieveData(recordID string) (interface{}, error) {
	encryptedData, err := api.ledgerService.RetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	data, err := api.encryptionService.DecryptData(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// IntegrationService handles the overall integration logic
type IntegrationService struct {
	apiClient *APIClient
}

// NewIntegrationService creates a new instance of IntegrationService
func NewIntegrationService(apiClient *APIClient) *IntegrationService {
	return &IntegrationService{
		apiClient: apiClient,
	}
}

// IntegrateETFData integrates ETF data from external sources into the ledger
func (service *IntegrationService) IntegrateETFData(etfID string) (string, error) {
	etfData, err := service.apiClient.FetchETFData(etfID)
	if err != nil {
		return "", err
	}

	recordID, err := service.apiClient.EncryptAndStoreData(etfData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// RecordTransaction records a transaction in the external API and ledger
func (service *IntegrationService) RecordTransaction(transactionData map[string]interface{}) (string, error) {
	transactionID, err := service.apiClient.PostTransaction(transactionData)
	if err != nil {
		return "", err
	}

	transactionData["transaction_id"] = transactionID
	recordID, err := service.apiClient.EncryptAndStoreData(transactionData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// RetrieveETFData retrieves ETF data from the ledger
func (service *IntegrationService) RetrieveETFData(recordID string) (map[string]interface{}, error) {
	data, err := service.apiClient.DecryptAndRetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	etfData, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to convert data to ETF data format")
	}

	return etfData, nil
}
