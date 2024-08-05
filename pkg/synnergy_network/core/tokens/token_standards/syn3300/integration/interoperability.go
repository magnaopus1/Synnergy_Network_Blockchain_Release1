package integration

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// InteroperabilityClientConfig contains configuration for interoperability clients
type InteroperabilityClientConfig struct {
	BaseURL       string
	APIKey        string
	Timeout       time.Duration
	RetryAttempts int
}

// InteroperabilityClient handles cross-chain and cross-platform interoperability
type InteroperabilityClient struct {
	config            InteroperabilityClientConfig
	encryptionService *encryption.EncryptionService
	ledgerService     *ledger.LedgerService
	client            *http.Client
}

// NewInteroperabilityClient creates a new instance of InteroperabilityClient
func NewInteroperabilityClient(config InteroperabilityClientConfig, encryptionService *encryption.EncryptionService, ledgerService *ledger.LedgerService) *InteroperabilityClient {
	return &InteroperabilityClient{
		config:            config,
		encryptionService: encryptionService,
		ledgerService:     ledgerService,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// SendRequest sends an HTTP request to the interoperability API
func (ic *InteroperabilityClient) SendRequest(method, endpoint string, payload interface{}) ([]byte, error) {
	url := ic.config.BaseURL + endpoint

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
	req.Header.Set("Authorization", "Bearer "+ic.config.APIKey)

	for i := 0; i < ic.config.RetryAttempts; i++ {
		resp, err := ic.client.Do(req)
		if err != nil {
			if i == ic.config.RetryAttempts-1 {
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

// SyncCrossChainData syncs cross-chain data with another blockchain platform
func (ic *InteroperabilityClient) SyncCrossChainData(chainData map[string]interface{}) error {
	endpoint := "/crosschain/sync"
	_, err := ic.SendRequest(http.MethodPost, endpoint, chainData)
	return err
}

// SyncCrossPlatformData syncs data with another platform
func (ic *InteroperabilityClient) SyncCrossPlatformData(platformData map[string]interface{}) error {
	endpoint := "/crossplatform/sync"
	_, err := ic.SendRequest(http.MethodPost, endpoint, platformData)
	return err
}

// EncryptAndStoreData encrypts and stores data using the ledger service
func (ic *InteroperabilityClient) EncryptAndStoreData(data interface{}) (string, error) {
	encryptedData, err := ic.encryptionService.EncryptData(data)
	if err != nil {
		return "", err
	}

	recordID, err := ic.ledgerService.RecordData(encryptedData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// DecryptAndRetrieveData retrieves and decrypts data using the ledger service
func (ic *InteroperabilityClient) DecryptAndRetrieveData(recordID string) (interface{}, error) {
	encryptedData, err := ic.ledgerService.RetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	data, err := ic.encryptionService.DecryptData(encryptedData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// InteroperabilityService handles the overall interoperability logic
type InteroperabilityService struct {
	interopClient *InteroperabilityClient
}

// NewInteroperabilityService creates a new instance of InteroperabilityService
func NewInteroperabilityService(interopClient *InteroperabilityClient) *InteroperabilityService {
	return &InteroperabilityService{
		interopClient: interopClient,
	}
}

// IntegrateCrossChainData integrates cross-chain data
func (service *InteroperabilityService) IntegrateCrossChainData(chainID string) (string, error) {
	chainData, err := service.interopClient.FetchChainData(chainID)
	if err != nil {
		return "", err
	}

	err = service.interopClient.SyncCrossChainData(chainData)
	if err != nil {
		return "", err
	}

	recordID, err := service.interopClient.EncryptAndStoreData(chainData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// IntegrateCrossPlatformData integrates cross-platform data
func (service *InteroperabilityService) IntegrateCrossPlatformData(platformID string) (string, error) {
	platformData, err := service.interopClient.FetchPlatformData(platformID)
	if err != nil {
		return "", err
	}

	err = service.interopClient.SyncCrossPlatformData(platformData)
	if err != nil {
		return "", err
	}

	recordID, err := service.interopClient.EncryptAndStoreData(platformData)
	if err != nil {
		return "", err
	}

	return recordID, nil
}

// RetrieveChainData retrieves chain data from the ledger
func (service *InteroperabilityService) RetrieveChainData(recordID string) (map[string]interface{}, error) {
	data, err := service.interopClient.DecryptAndRetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	chainData, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to convert data to chain data format")
	}

	return chainData, nil
}

// RetrievePlatformData retrieves platform data from the ledger
func (service *InteroperabilityService) RetrievePlatformData(recordID string) (map[string]interface{}, error) {
	data, err := service.interopClient.DecryptAndRetrieveData(recordID)
	if err != nil {
		return nil, err
	}

	platformData, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to convert data to platform data format")
	}

	return platformData, nil
}

// FetchChainData fetches chain data from the external API
func (ic *InteroperabilityClient) FetchChainData(chainID string) (map[string]interface{}, error) {
	endpoint := "/chain/data/" + chainID
	response, err := ic.SendRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var chainData map[string]interface{}
	if err := json.Unmarshal(response, &chainData); err != nil {
		return nil, err
	}

	return chainData, nil
}

// FetchPlatformData fetches platform data from the external API
func (ic *InteroperabilityClient) FetchPlatformData(platformID string) (map[string]interface{}, error) {
	endpoint := "/platform/data/" + platformID
	response, err := ic.SendRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var platformData map[string]interface{}
	if err := json.Unmarshal(response, &platformData); err != nil {
		return nil, err
	}

	return platformData, nil
}
