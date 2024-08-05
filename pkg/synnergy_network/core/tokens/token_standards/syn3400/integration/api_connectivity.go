package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type APIConnectivity struct {
	BaseURL       string
	APIKey        string
	Timeout       time.Duration
	Headers       map[string]string
	RateLimit     int
	LastRequest   time.Time
}

// InitializeAPIConnectivity initializes the API connectivity structure
func InitializeAPIConnectivity(baseURL, apiKey string, timeout time.Duration, rateLimit int) *APIConnectivity {
	return &APIConnectivity{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		Timeout:   timeout,
		RateLimit: rateLimit,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": fmt.Sprintf("Bearer %s", apiKey),
		},
	}
}

// SendRequest sends an HTTP request to the specified endpoint
func (api *APIConnectivity) SendRequest(endpoint string, method string, payload interface{}) (*http.Response, error) {
	// Rate limiting
	if time.Since(api.LastRequest).Seconds() < float64(1)/float64(api.RateLimit) {
		return nil, errors.New("rate limit exceeded")
	}
	api.LastRequest = time.Now()

	// Marshal payload to JSON
	var jsonPayload []byte
	var err error
	if payload != nil {
		jsonPayload, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	// Create HTTP request
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", api.BaseURL, endpoint), bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}

	// Add headers
	for key, value := range api.Headers {
		req.Header.Set(key, value)
	}

	// Send HTTP request
	client := &http.Client{Timeout: api.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Check response status
	if resp.StatusCode >= 400 {
		return nil, errors.New(fmt.Sprintf("API request failed with status code: %d", resp.StatusCode))
	}

	return resp, nil
}

// Get retrieves data from the specified endpoint
func (api *APIConnectivity) Get(endpoint string) (*http.Response, error) {
	return api.SendRequest(endpoint, "GET", nil)
}

// Post sends data to the specified endpoint
func (api *APIConnectivity) Post(endpoint string, payload interface{}) (*http.Response, error) {
	return api.SendRequest(endpoint, "POST", payload)
}

// Put updates data at the specified endpoint
func (api *APIConnectivity) Put(endpoint string, payload interface{}) (*http.Response, error) {
	return api.SendRequest(endpoint, "PUT", payload)
}

// Delete removes data from the specified endpoint
func (api *APIConnectivity) Delete(endpoint string) (*http.Response, error) {
	return api.SendRequest(endpoint, "DELETE", nil)
}

// ParseResponse parses the HTTP response into the provided target
func (api *APIConnectivity) ParseResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}
