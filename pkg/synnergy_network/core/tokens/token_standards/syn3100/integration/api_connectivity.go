package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
)

// APIClient represents a client for interacting with external APIs.
type APIClient struct {
	BaseURL string
	Timeout time.Duration
	Client  *http.Client
}

// NewAPIClient initializes a new APIClient instance.
func NewAPIClient(baseURL string, timeout time.Duration) *APIClient {
	return &APIClient{
		BaseURL: baseURL,
		Timeout: timeout,
		Client:  &http.Client{Timeout: timeout},
	}
}

// APIConnectivity manages the integration and connectivity with external APIs.
type APIConnectivity struct {
	sync.RWMutex
	apiClients map[string]*APIClient
}

// NewAPIConnectivity initializes a new APIConnectivity instance.
func NewAPIConnectivity() *APIConnectivity {
	return &APIConnectivity{
		apiClients: make(map[string]*APIClient),
	}
}

// RegisterAPIClient registers a new API client for a specific service.
func (ac *APIConnectivity) RegisterAPIClient(serviceName, baseURL string, timeout time.Duration) {
	ac.Lock()
	defer ac.Unlock()
	ac.apiClients[serviceName] = NewAPIClient(baseURL, timeout)
}

// GetAPIClient retrieves the API client for a specific service.
func (ac *APIConnectivity) GetAPIClient(serviceName string) (*APIClient, error) {
	ac.RLock()
	defer ac.RUnlock()
	client, exists := ac.apiClients[serviceName]
	if !exists {
		return nil, errors.New("API client not found for service: " + serviceName)
	}
	return client, nil
}

// Post sends a POST request to an external API.
func (ac *APIConnectivity) Post(serviceName, endpoint string, data interface{}) (*http.Response, error) {
	client, err := ac.GetAPIClient(serviceName)
	if err != nil {
		return nil, err
	}
	url := client.BaseURL + endpoint
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Client.Do(req)
}

// Get sends a GET request to an external API.
func (ac *APIConnectivity) Get(serviceName, endpoint string) (*http.Response, error) {
	client, err := ac.GetAPIClient(serviceName)
	if err != nil {
		return nil, err
	}
	url := client.BaseURL + endpoint
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return client.Client.Do(req)
}

// FetchEmploymentMetadata fetches employment metadata from an external API.
func (ac *APIConnectivity) FetchEmploymentMetadata(serviceName, endpoint string) (assets.EmploymentMetadata, error) {
	resp, err := ac.Get(serviceName, endpoint)
	if err != nil {
		return assets.EmploymentMetadata{}, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return assets.EmploymentMetadata{}, err
	}
	var metadata assets.EmploymentMetadata
	err = json.Unmarshal(body, &metadata)
	if err != nil {
		return assets.EmploymentMetadata{}, err
	}
	return metadata, nil
}

// PostEvent sends an event to an external API.
func (ac *APIConnectivity) PostEvent(serviceName, endpoint string, event events.Event) (*http.Response, error) {
	return ac.Post(serviceName, endpoint, event)
}

// PostTransaction sends a transaction record to an external API.
func (ac *APIConnectivity) PostTransaction(serviceName, endpoint string, transaction ledger.TransactionRecord) (*http.Response, error) {
	return ac.Post(serviceName, endpoint, transaction)
}

// RegisterEventAPI registers an API client for posting events.
func (ac *APIConnectivity) RegisterEventAPI(serviceName, baseURL string, timeout time.Duration) {
	ac.RegisterAPIClient(serviceName, baseURL, timeout)
}

// RegisterTransactionAPI registers an API client for posting transactions.
func (ac *APIConnectivity) RegisterTransactionAPI(serviceName, baseURL string, timeout time.Duration) {
	ac.RegisterAPIClient(serviceName, baseURL, timeout)
}

// HandleAPIResponse processes the response from an external API.
func HandleAPIResponse(resp *http.Response) (string, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return string(body), nil
	}
	return "", errors.New("API request failed with status: " + resp.Status + ", response: " + string(body))
}
