package integration

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "net/http"
    "time"
)

// APIClient is responsible for managing API connectivity and interactions
type APIClient struct {
    baseURL    string
    apiKey     string
    httpClient *http.Client
}

// NewAPIClient creates a new APIClient
func NewAPIClient(baseURL, apiKey string) *APIClient {
    return &APIClient{
        baseURL:    baseURL,
        apiKey:     apiKey,
        httpClient: &http.Client{Timeout: 10 * time.Second},
    }
}

// sendRequest sends an HTTP request to the specified endpoint with the given method and data
func (client *APIClient) sendRequest(endpoint, method string, data interface{}) ([]byte, error) {
    url := fmt.Sprintf("%s%s", client.baseURL, endpoint)
    jsonData, err := json.Marshal(data)
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.apiKey))

    resp, err := client.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("error: received status code %d", resp.StatusCode)
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    return body, nil
}

// CreateEvent sends a request to create a new event
func (client *APIClient) CreateEvent(eventData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest("/events", "POST", eventData)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// GetEvent sends a request to get an event by ID
func (client *APIClient) GetEvent(eventID string) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/events/%s", eventID), "GET", nil)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// UpdateEvent sends a request to update an event by ID
func (client *APIClient) UpdateEvent(eventID string, eventData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/events/%s", eventID), "PUT", eventData)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// DeleteEvent sends a request to delete an event by ID
func (client *APIClient) DeleteEvent(eventID string) error {
    _, err := client.sendRequest(fmt.Sprintf("/events/%s", eventID), "DELETE", nil)
    return err
}

// AddTicket sends a request to add a new ticket to an event
func (client *APIClient) AddTicket(eventID string, ticketData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/events/%s/tickets", eventID), "POST", ticketData)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// GetTicket sends a request to get a ticket by ID
func (client *APIClient) GetTicket(eventID, ticketID string) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/events/%s/tickets/%s", eventID, ticketID), "GET", nil)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// TransferTicket sends a request to transfer a ticket
func (client *APIClient) TransferTicket(ticketID string, transferData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/tickets/%s/transfer", ticketID), "POST", transferData)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// RevokeTicket sends a request to revoke a ticket
func (client *APIClient) RevokeTicket(ticketID string, revokeData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/tickets/%s/revoke", ticketID), "POST", revokeData)
    if err != nil {
        return nil, err
    }

    var response map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// ListEvents sends a request to list all events
func (client *APIClient) ListEvents() ([]map[string]interface{}, error) {
    responseBody, err := client.sendRequest("/events", "GET", nil)
    if err != nil {
        return nil, err
    }

    var response []map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}

// ListTickets sends a request to list all tickets for an event
func (client *APIClient) ListTickets(eventID string) ([]map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/events/%s/tickets", eventID), "GET", nil)
    if err != nil {
        return nil, err
    }

    var response []map[string]interface{}
    err = json.Unmarshal(responseBody, &response)
    if err != nil {
        return nil, err
    }

    return response, nil
}
