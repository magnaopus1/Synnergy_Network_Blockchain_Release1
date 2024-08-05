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
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// HRPlatformClient represents a client for interacting with HR platforms.
type HRPlatformClient struct {
	BaseURL string
	Timeout time.Duration
	Client  *http.Client
}

// NewHRPlatformClient initializes a new HRPlatformClient instance.
func NewHRPlatformClient(baseURL string, timeout time.Duration) *HRPlatformClient {
	return &HRPlatformClient{
		BaseURL: baseURL,
		Timeout: timeout,
		Client:  &http.Client{Timeout: timeout},
	}
}

// HRPlatformsIntegration manages the integration and connectivity with HR platforms.
type HRPlatformsIntegration struct {
	sync.RWMutex
	clients map[string]*HRPlatformClient
}

// NewHRPlatformsIntegration initializes a new HRPlatformsIntegration instance.
func NewHRPlatformsIntegration() *HRPlatformsIntegration {
	return &HRPlatformsIntegration{
		clients: make(map[string]*HRPlatformClient),
	}
}

// RegisterHRPlatformClient registers a new HR platform client.
func (hr *HRPlatformsIntegration) RegisterHRPlatformClient(platformName, baseURL string, timeout time.Duration) {
	hr.Lock()
	defer hr.Unlock()
	hr.clients[platformName] = NewHRPlatformClient(baseURL, timeout)
}

// GetHRPlatformClient retrieves the HR platform client for a specific platform.
func (hr *HRPlatformsIntegration) GetHRPlatformClient(platformName string) (*HRPlatformClient, error) {
	hr.RLock()
	defer hr.RUnlock()
	client, exists := hr.clients[platformName]
	if !exists {
		return nil, errors.New("HR platform client not found for platform: " + platformName)
	}
	return client, nil
}

// FetchEmployeeData fetches employee data from an HR platform.
func (hr *HRPlatformsIntegration) FetchEmployeeData(platformName, endpoint string) (assets.EmploymentMetadata, error) {
	client, err := hr.GetHRPlatformClient(platformName)
	if err != nil {
		return assets.EmploymentMetadata{}, err
	}
	url := client.BaseURL + endpoint
	resp, err := client.Client.Get(url)
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

// PostEmployeeData sends employee data to an HR platform.
func (hr *HRPlatformsIntegration) PostEmployeeData(platformName, endpoint string, data assets.EmploymentMetadata) (*http.Response, error) {
	client, err := hr.GetHRPlatformClient(platformName)
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

// UpdateEmployeeData updates employee data on an HR platform.
func (hr *HRPlatformsIntegration) UpdateEmployeeData(platformName, endpoint string, data assets.EmploymentMetadata) (*http.Response, error) {
	client, err := hr.GetHRPlatformClient(platformName)
	if err != nil {
		return nil, err
	}
	url := client.BaseURL + endpoint
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Client.Do(req)
}

// DeleteEmployeeData deletes employee data from an HR platform.
func (hr *HRPlatformsIntegration) DeleteEmployeeData(platformName, endpoint string) (*http.Response, error) {
	client, err := hr.GetHRPlatformClient(platformName)
	if err != nil {
		return nil, err
	}
	url := client.BaseURL + endpoint
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	return client.Client.Do(req)
}

// HandleAPIResponse processes the response from an HR platform.
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
