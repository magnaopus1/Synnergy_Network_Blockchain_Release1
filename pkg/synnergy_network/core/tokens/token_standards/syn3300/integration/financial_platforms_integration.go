package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// FinancialPlatformClientConfig contains configuration for financial platform clients
type FinancialPlatformClientConfig struct {
	BaseURL       string
	APIKey        string
	Timeout       time.Duration
	RetryAttempts int
}

// FinancialPlatformClient handles connectivity to financial platforms
type FinancialPlatformClient struct {
	config            FinancialPlatformClientConfig
	encryptionService *encryption.EncryptionService
	ledgerService     *ledger.LedgerService
	client            *http.Client
}

// NewFinancialPlatformClient creates a new instance of FinancialPlatformClient
func NewFinancialPlatformClient(config FinancialPlatformClientConfig, encryptionService *encryption.EncryptionService, ledgerService *ledger.LedgerService) *FinancialPlatformClient {
	return &FinancialPlatformClient{
		config:            config,
		encryptionService: encryptionService,
		ledgerService:     ledgerService,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// SendRequest sends an HTTP request to the financial platform API
func (fp *FinancialPlatformClient) SendRequest(method, endpoint string, payload interface{}) ([]byte, error) {
	url := fp.config.BaseURL + endpoint

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
	req.Header.Set("Authorization", "Bearer "+fp.config.APIKey)

	for i := 0; i < fp.config.RetryAttempts; i++ {
		resp, err := fp.client.Do(req)
		if err != nil {
			if i == fp.config.RetryAttempts-1 {
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

// SyncETFData syncs ETF data with the financial platform
func (fp *FinancialPlatformClient) SyncETFData(etfData map[string]interface{}) error {
	endpoint := "/etf/sync"
	_, err := fp.SendRequest(http.MethodPost, endpoint, etfData)
	return err
}

// SyncTransactionData syncs transaction data with the financial platform
func (fp *FinancialPlatformClient) SyncTransactionData(transactionData map[string]interface{}) error {
	endpoint := "/transaction/sync"
	_, err := fp.SendRequest(http.MethodPost, endpoint, transactionData)
	return err
}

// EncryptAndStoreData encrypts and stores data using the ledger service
func (fp *FinancialPlatformClient) EncryptAndStoreData(data interface{}) (string, error) {
	encryptedData, err := fp.encryptionService.EncryptData(data)
	if err != nil {
		return "", err
	}

	recordID, err := fp.ledgerService.RecordData(encryptedData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// DecryptAndRetrieveData retrieves and decrypts data using the ledger service
func (fp *FinancialPlatformClient) DecryptAndRetrieveData(recordID string) (interface{}, error) {
	encryptedData, err := fp.ledgerService.RetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	data, err := fp.encryptionService.DecryptData(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// FinancialPlatformIntegrationService handles the overall integration logic with financial platforms
type FinancialPlatformIntegrationService struct {
	platformClient *FinancialPlatformClient
}

// NewFinancialPlatformIntegrationService creates a new instance of FinancialPlatformIntegrationService
func NewFinancialPlatformIntegrationService(platformClient *FinancialPlatformClient) *FinancialPlatformIntegrationService {
	return &FinancialPlatformIntegrationService{
		platformClient: platformClient,
	}
}

// IntegrateETFData integrates ETF data with the financial platform
func (service *FinancialPlatformIntegrationService) IntegrateETFData(etfID string) (string, error) {
	etfData, err := service.platformClient.FetchETFData(etfID)
	if err != nil {
		return "", err
	}

	err = service.platformClient.SyncETFData(etfData)
	if err != nil {
		return "", err
	}

	recordID, err := service.platformClient.EncryptAndStoreData(etfData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// RecordTransaction records a transaction in the financial platform and ledger
func (service *FinancialPlatformIntegrationService) RecordTransaction(transactionData map[string]interface{}) (string, error) {
	err := service.platformClient.SyncTransactionData(transactionData)
	if err != nil {
		return "", err
	}

	recordID, err := service.platformClient.EncryptAndStoreData(transactionData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// RetrieveETFData retrieves ETF data from the ledger
func (service *FinancialPlatformIntegrationService) RetrieveETFData(recordID string) (map[string]interface{}, error) {
	data, err := service.platformClient.DecryptAndRetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	etfData, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to convert data to ETF data format")
	}

	return etfData, nil
}

// FetchETFData fetches ETF data from the external API
func (fp *FinancialPlatformClient) FetchETFData(etfID string) (map[string]interface{}, error) {
	endpoint := "/etf/data/" + etfID
	response, err := fp.SendRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var etfData map[string]interface{}
	if err := json.Unmarshal(response, &etfData); err != nil {
		return nil, err
	}

	return etfData, nil
}
