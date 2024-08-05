// Package integration provides functionalities to integrate SYN3200 tokens with external billing platforms.
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

// BillingPlatformClient represents the client to interact with external billing platforms.
type BillingPlatformClient struct {
	BaseURL    string
	HTTPClient *http.Client
	APIKey     string
}

// NewBillingPlatformClient creates a new instance of BillingPlatformClient.
func NewBillingPlatformClient(baseURL, apiKey string) *BillingPlatformClient {
	return &BillingPlatformClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		APIKey: apiKey,
	}
}

// BillingPlatformRequest represents a generic request structure to the billing platform.
type BillingPlatformRequest struct {
	Endpoint string
	Method   string
	Body     interface{}
	Headers  map[string]string
}

// BillingPlatformResponse represents a generic response structure from the billing platform.
type BillingPlatformResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string][]string
}

// SendRequest sends a request to the specified billing platform endpoint.
func (client *BillingPlatformClient) SendRequest(request BillingPlatformRequest) (*BillingPlatformResponse, error) {
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

	return &BillingPlatformResponse{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}, nil
}

// BillingPlatformsIntegration handles integration with external billing platforms for SYN3200 tokens.
type BillingPlatformsIntegration struct {
	BillingClient   *BillingPlatformClient
	BillLedger      *ledger.BillLedger
	MetadataLedger  *assets.MetadataLedger
	OwnershipLedger *assets.OwnershipLedger
}

// NewBillingPlatformsIntegration creates a new instance of BillingPlatformsIntegration.
func NewBillingPlatformsIntegration(billingClient *BillingPlatformClient, billLedger *ledger.BillLedger, metadataLedger *assets.MetadataLedger, ownershipLedger *assets.OwnershipLedger) *BillingPlatformsIntegration {
	return &BillingPlatformsIntegration{
		BillingClient:   billingClient,
		BillLedger:      billLedger,
		MetadataLedger:  metadataLedger,
		OwnershipLedger: ownershipLedger,
	}
}

// SyncBillDataWithPlatform syncs bill data with an external billing platform.
func (bpi *BillingPlatformsIntegration) SyncBillDataWithPlatform(billID string) error {
	bill, err := bpi.BillLedger.GetBill(billID)
	if err != nil {
		return err
	}

	request := BillingPlatformRequest{
		Endpoint: "/sync/bill",
		Method:   http.MethodPost,
		Body:     bill,
		Headers:  map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync bill data with platform")
	}

	return nil
}

// SyncMetadataWithPlatform syncs bill metadata with an external billing platform.
func (bpi *BillingPlatformsIntegration) SyncMetadataWithPlatform(billID string) error {
	metadata, err := bpi.MetadataLedger.GetMetadata(billID)
	if err != nil {
		return err
	}

	request := BillingPlatformRequest{
		Endpoint: "/sync/metadata",
		Method:   http.MethodPost,
		Body:     metadata,
		Headers:  map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync metadata with platform")
	}

	return nil
}

// SyncOwnershipRecordWithPlatform syncs ownership records with an external billing platform.
func (bpi *BillingPlatformsIntegration) SyncOwnershipRecordWithPlatform(billID string) error {
	ownershipRecord, err := bpi.OwnershipLedger.GetOwnershipRecord(billID)
	if err != nil {
		return err
	}

	request := BillingPlatformRequest{
		Endpoint: "/sync/ownership",
		Method:   http.MethodPost,
		Body:     ownershipRecord,
		Headers:  map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to sync ownership record with platform")
	}

	return nil
}

// RetrieveBillDataFromPlatform retrieves bill data from an external billing platform.
func (bpi *BillingPlatformsIntegration) RetrieveBillDataFromPlatform(billID string) (*assets.Bill, error) {
	request := BillingPlatformRequest{
		Endpoint: "/retrieve/bill/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve bill data from platform")
	}

	var bill assets.Bill
	err = json.Unmarshal(response.Body, &bill)
	if err != nil {
		return nil, err
	}

	return &bill, nil
}

// RetrieveMetadataFromPlatform retrieves bill metadata from an external billing platform.
func (bpi *BillingPlatformsIntegration) RetrieveMetadataFromPlatform(billID string) (*assets.BillMetadata, error) {
	request := BillingPlatformRequest{
		Endpoint: "/retrieve/metadata/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve metadata from platform")
	}

	var metadata assets.BillMetadata
	err = json.Unmarshal(response.Body, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// RetrieveOwnershipRecordFromPlatform retrieves ownership records from an external billing platform.
func (bpi *BillingPlatformsIntegration) RetrieveOwnershipRecordFromPlatform(billID string) (*assets.OwnershipRecord, error) {
	request := BillingPlatformRequest{
		Endpoint: "/retrieve/ownership/" + billID,
		Method:   http.MethodGet,
		Headers:  map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve ownership record from platform")
	}

	var ownershipRecord assets.OwnershipRecord
	err = json.Unmarshal(response.Body, &ownershipRecord)
	if err != nil {
		return nil, err
	}

	return &ownershipRecord, nil
}

// ReportSyncStatusToPlatform reports the status of synchronization with an external billing platform.
func (bpi *BillingPlatformsIntegration) ReportSyncStatusToPlatform(status string) error {
	request := BillingPlatformRequest{
		Endpoint: "/report/status",
		Method:   http.MethodPost,
		Body: map[string]string{
			"status": status,
		},
		Headers: map[string]string{},
	}

	response, err := bpi.BillingClient.SendRequest(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return errors.New("failed to report sync status to platform")
	}

	return nil
}
