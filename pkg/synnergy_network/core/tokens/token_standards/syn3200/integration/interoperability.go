// Package integration provides functionalities to ensure interoperability of SYN3200 tokens with other blockchain networks.
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

// InteroperabilityClient represents the client to interact with other blockchain networks.
type InteroperabilityClient struct {
	BaseURL    string
	HTTPClient *http.Client
	APIKey     string
}

// NewInteroperabilityClient creates a new instance of InteroperabilityClient.
func NewInteroperabilityClient(baseURL, apiKey string) *InteroperabilityClient {
	return &InteroperabilityClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		APIKey: apiKey,
	}
}

// InteroperabilityRequest represents a generic request structure for interoperability.
type InteroperabilityRequest struct {
	Endpoint string
	Method   string
	Body     interface{}
	Headers  map[string]string
}

// InteroperabilityResponse represents a generic response structure for interoperability.
type InteroperabilityResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string][]string
}

// SendRequest sends a request to the specified blockchain network endpoint.
func (client *InteroperabilityClient) SendRequest(request InteroperabilityRequest) (*InteroperabilityResponse, error) {
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

	return &InteroperabilityResponse{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}, nil
}

// InteroperabilityIntegration handles interoperability with other blockchain networks for SYN3200 tokens.
type InteroperabilityIntegration struct {
	InteroperabilityClient *InteroperabilityClient
	BillLedger             *ledger.BillLedger
	MetadataLedger         *assets.MetadataLedger
	OwnershipLedger        *assets.OwnershipLedger
}

// NewInteroperabilityIntegration creates a new instance of InteroperabilityIntegration.
func NewInteroperabilityIntegration(interoperabilityClient *InteroperabilityClient, billLedger *ledger.BillLedger, metadataLedger *assets.MetadataLedger, ownershipLedger *assets.OwnershipLedger) *InteroperabilityIntegration {
	return &InteroperabilityIntegration{
		InteroperabilityClient: interoperabilityClient,
		BillLedger:             billLedger,
		MetadataLedger:         metadataLedger,
		OwnershipLedger:        ownershipLedger,
	}
}

// SyncBillDataWithNetwork syncs bill data with another blockchain network.
func (ii *InteroperabilityIntegration) SyncBillDataWithNetwork(billID string) error {
	bill, err := ii.BillLedger.GetBill(billID)
	if err != nil {
		return err
	}

	request := InteroperabilityRequest{
		Endpoint: "/sync/bill",
		Method:   http.MethodPost,
		Body:     bill,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync bill data with network")
	}

	return nil
}

// SyncMetadataWithNetwork syncs bill metadata with another blockchain network.
func (ii *InteroperabilityIntegration) SyncMetadataWithNetwork(billID string) error {
	metadata, err := ii.MetadataLedger.GetMetadata(billID)
	if err != nil {
		return err
	}

	request := InteroperabilityRequest{
		Endpoint: "/sync/metadata",
		Method:   http.MethodPost,
		Body:     metadata,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync metadata with network")
	}

	return nil
}

// SyncOwnershipRecordWithNetwork syncs ownership records with another blockchain network.
func (ii *InteroperabilityIntegration) SyncOwnershipRecordWithNetwork(billID string) error {
	ownershipRecord, err := ii.OwnershipLedger.GetOwnershipRecord(billID)
	if err != nil {
		return err
	}

	request := InteroperabilityRequest{
		Endpoint: "/sync/ownership",
		Method:   http.MethodPost,
		Body:     ownershipRecord,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync ownership record with network")
	}

	return nil
}

// RetrieveBillDataFromNetwork retrieves bill data from another blockchain network.
func (ii *InteroperabilityIntegration) RetrieveBillDataFromNetwork(billID string) (*assets.Bill, error) {
	request := InteroperabilityRequest{
		Endpoint: "/retrieve/bill/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve bill data from network")
	}

	var bill assets.Bill
	err = json.Unmarshal(response.Body, &bill)
	if err != nil {
		return nil, err
	}

	return &bill, nil
}

// RetrieveMetadataFromNetwork retrieves bill metadata from another blockchain network.
func (ii *InteroperabilityIntegration) RetrieveMetadataFromNetwork(billID string) (*assets.BillMetadata, error) {
	request := InteroperabilityRequest{
		Endpoint: "/retrieve/metadata/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve metadata from network")
	}

	var metadata assets.BillMetadata
	err = json.Unmarshal(response.Body, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// RetrieveOwnershipRecordFromNetwork retrieves ownership records from another blockchain network.
func (ii *InteroperabilityIntegration) RetrieveOwnershipRecordFromNetwork(billID string) (*assets.OwnershipRecord, error) {
	request := InteroperabilityRequest{
		Endpoint: "/retrieve/ownership/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve ownership record from network")
	}

	var ownershipRecord assets.OwnershipRecord
	err = json.Unmarshal(response.Body, &ownershipRecord)
	if err != nil {
		return nil, err
	}

	return &ownershipRecord, nil
}

// ReportSyncStatusToNetwork reports the status of synchronization with another blockchain network.
func (ii *InteroperabilityIntegration) ReportSyncStatusToNetwork(status string) error {
	request := InteroperabilityRequest{
		Endpoint: "/report/status",
		Method:   http.MethodPost,
		Body: map[string]string{
			"status": status,
		},
		Headers: map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to report sync status to network")
	}

	return nil
}

// ValidateNetworkConnection validates the connection to another blockchain network.
func (ii *InteroperabilityIntegration) ValidateNetworkConnection() error {
	request := InteroperabilityRequest{
		Endpoint: "/validate/connection",
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := ii.InteroperabilityClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to validate network connection")
	}

	return nil
}
