// Package integration provides functionalities to integrate SYN3200 tokens with external APIs.
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"synnergy_network/core/tokens/token_standards/syn3200/assets"
	"synnergy_network/core/tokens/token_standards/syn3200/ledger"
)

// APIClient represents the client to interact with external APIs.
type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	APIKey     string
}

// NewAPIClient creates a new instance of APIClient.
func NewAPIClient(baseURL, apiKey string) *APIClient {
	return &APIClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		APIKey: apiKey,
	}
}

// APIRequest represents a generic API request structure.
type APIRequest struct {
	Endpoint string
	Method   string
	Body     interface{}
	Headers  map[string]string
}

// APIResponse represents a generic API response structure.
type APIResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string][]string
}

// SendRequest sends a request to the specified API endpoint.
func (client *APIClient) SendRequest(request APIRequest) (*APIResponse, error) {
	var reqBody []byte
	var err error

	if request.Body != nil {
		reqBody, err = json.Marshal(request.Body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(request.Method, client.BaseURL+request.Endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	for key, value := range request.Headers {
		req.Header.Set(key, value)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.APIKey)

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &APIResponse{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}, nil
}

// ExternalAPIIntegration handles integration with external APIs for SYN3200 tokens.
type ExternalAPIIntegration struct {
	APIClient       *APIClient
	BillLedger      *ledger.BillLedger
	MetadataLedger  *assets.MetadataLedger
	OwnershipLedger *assets.OwnershipLedger
}

// NewExternalAPIIntegration creates a new instance of ExternalAPIIntegration.
func NewExternalAPIIntegration(apiClient *APIClient, billLedger *ledger.BillLedger, metadataLedger *assets.MetadataLedger, ownershipLedger *assets.OwnershipLedger) *ExternalAPIIntegration {
	return &ExternalAPIIntegration{
		APIClient:       apiClient,
		BillLedger:      billLedger,
		MetadataLedger:  metadataLedger,
		OwnershipLedger: ownershipLedger,
	}
}

// SyncBillData syncs bill data with an external API.
func (eai *ExternalAPIIntegration) SyncBillData(billID string) error {
	bill, err := eai.BillLedger.GetBill(billID)
	if err != nil {
		return err
	}

	request := APIRequest{
		Endpoint: "/sync/bill",
		Method:   http.MethodPost,
		Body:     bill,
		Headers:  map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync bill data")
	}

	return nil
}

// SyncMetadata syncs bill metadata with an external API.
func (eai *ExternalAPIIntegration) SyncMetadata(billID string) error {
	metadata, err := eai.MetadataLedger.GetMetadata(billID)
	if err != nil {
		return err
	}

	request := APIRequest{
		Endpoint: "/sync/metadata",
		Method:   http.MethodPost,
		Body:     metadata,
		Headers:  map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync metadata")
	}

	return nil
}

// SyncOwnershipRecord syncs ownership records with an external API.
func (eai *ExternalAPIIntegration) SyncOwnershipRecord(billID string) error {
	ownershipRecord, err := eai.OwnershipLedger.GetOwnershipRecord(billID)
	if err != nil {
		return err
	}

	request := APIRequest{
		Endpoint: "/sync/ownership",
		Method:   http.MethodPost,
		Body:     ownershipRecord,
		Headers:  map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync ownership record")
	}

	return nil
}

// RetrieveExternalBillData retrieves bill data from an external API.
func (eai *ExternalAPIIntegration) RetrieveExternalBillData(billID string) (*assets.Bill, error) {
	request := APIRequest{
		Endpoint: "/retrieve/bill/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve external bill data")
	}

	var bill assets.Bill
	err = json.Unmarshal(response.Body, &bill)
	if err != nil {
		return nil, err
	}

	return &bill, nil
}

// RetrieveExternalMetadata retrieves bill metadata from an external API.
func (eai *ExternalAPIIntegration) RetrieveExternalMetadata(billID string) (*assets.BillMetadata, error) {
	request := APIRequest{
		Endpoint: "/retrieve/metadata/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve external metadata")
	}

	var metadata assets.BillMetadata
	err = json.Unmarshal(response.Body, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// RetrieveExternalOwnershipRecord retrieves ownership records from an external API.
func (eai *ExternalAPIIntegration) RetrieveExternalOwnershipRecord(billID string) (*assets.OwnershipRecord, error) {
	request := APIRequest{
		Endpoint: "/retrieve/ownership/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve external ownership record")
	}

	var ownershipRecord assets.OwnershipRecord
	err = json.Unmarshal(response.Body, &ownershipRecord)
	if err != nil {
		return nil, err
	}

	return &ownershipRecord, nil
}

// ReportSyncStatus reports the status of synchronization with an external API.
func (eai *ExternalAPIIntegration) ReportSyncStatus(status string) error {
	request := APIRequest{
		Endpoint: "/report/status",
		Method:   http.MethodPost,
		Body: map[string]string{
			"status": status,
		},
		Headers: map[string]string{},
	}

	response, err := eai.APIClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to report sync status")
	}

	return nil
}
