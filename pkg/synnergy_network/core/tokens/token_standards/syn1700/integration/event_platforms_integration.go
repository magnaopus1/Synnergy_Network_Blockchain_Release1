package integration

import (
    "encoding/json"
    "errors"
    "fmt"
    "time"
    "net/http"
    "bytes"
)

// EventPlatformClient manages the integration with external event platforms
type EventPlatformClient struct {
    baseURL    string
    apiKey     string
    httpClient *http.Client
}

// NewEventPlatformClient creates a new EventPlatformClient
func NewEventPlatformClient(baseURL, apiKey string) *EventPlatformClient {
    return &EventPlatformClient{
        baseURL:    baseURL,
        apiKey:     apiKey,
        httpClient: &http.Client{Timeout: 10 * time.Second},
    }
}

// sendRequest sends an HTTP request to the specified endpoint with the given method and data
func (client *EventPlatformClient) sendRequest(endpoint, method string, data interface{}) ([]byte, error) {
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

// SyncEvent synchronizes an event with the external platform
func (client *EventPlatformClient) SyncEvent(eventData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest("/external/events/sync", "POST", eventData)
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

// SyncTicket synchronizes a ticket with the external platform
func (client *EventPlatformClient) SyncTicket(ticketData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest("/external/tickets/sync", "POST", ticketData)
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

// FetchExternalEvents fetches events from the external platform
func (client *EventPlatformClient) FetchExternalEvents() ([]map[string]interface{}, error) {
    responseBody, err := client.sendRequest("/external/events", "GET", nil)
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

// FetchExternalTickets fetches tickets from the external platform
func (client *EventPlatformClient) FetchExternalTickets(eventID string) ([]map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/external/events/%s/tickets", eventID), "GET", nil)
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

// ValidateExternalTicket validates a ticket with the external platform
func (client *EventPlatformClient) ValidateExternalTicket(ticketID string, validationData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/external/tickets/%s/validate", ticketID), "POST", validationData)
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

// RevokeExternalTicket revokes a ticket on the external platform
func (client *EventPlatformClient) RevokeExternalTicket(ticketID string, revokeData map[string]interface{}) (map[string]interface{}, error) {
    responseBody, err := client.sendRequest(fmt.Sprintf("/external/tickets/%s/revoke", ticketID), "POST", revokeData)
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

// EventIntegrationManager manages the integration logic between SYN1700 and external platforms
type EventIntegrationManager struct {
    platformClient *EventPlatformClient
}

// NewEventIntegrationManager creates a new EventIntegrationManager
func NewEventIntegrationManager(platformClient *EventPlatformClient) *EventIntegrationManager {
    return &EventIntegrationManager{
        platformClient: platformClient,
    }
}

// SyncEventWithPlatform syncs an event with an external platform
func (manager *EventIntegrationManager) SyncEventWithPlatform(eventID string, eventData map[string]interface{}) (map[string]interface{}, error) {
    response, err := manager.platformClient.SyncEvent(eventData)
    if err != nil {
        return nil, err
    }
    return response, nil
}

// SyncTicketWithPlatform syncs a ticket with an external platform
func (manager *EventIntegrationManager) SyncTicketWithPlatform(eventID, ticketID string, ticketData map[string]interface{}) (map[string]interface{}, error) {
    response, err := manager.platformClient.SyncTicket(ticketData)
    if err != nil {
        return nil, err
    }
    return response, nil
}

// FetchEventsFromPlatform fetches events from an external platform
func (manager *EventIntegrationManager) FetchEventsFromPlatform() ([]map[string]interface{}, error) {
    events, err := manager.platformClient.FetchExternalEvents()
    if err != nil {
        return nil, err
    }
    return events, nil
}

// FetchTicketsFromPlatform fetches tickets for an event from an external platform
func (manager *EventIntegrationManager) FetchTicketsFromPlatform(eventID string) ([]map[string]interface{}, error) {
    tickets, err := manager.platformClient.FetchExternalTickets(eventID)
    if err != nil {
        return nil, err
    }
    return tickets, nil
}

// ValidateTicketWithPlatform validates a ticket with an external platform
func (manager *EventIntegrationManager) ValidateTicketWithPlatform(ticketID string, validationData map[string]interface{}) (map[string]interface{}, error) {
    response, err := manager.platformClient.ValidateExternalTicket(ticketID, validationData)
    if err != nil {
        return nil, err
    }
    return response, nil
}

// RevokeTicketWithPlatform revokes a ticket on an external platform
func (manager *EventIntegrationManager) RevokeTicketWithPlatform(ticketID string, revokeData map[string]interface{}) (map[string]interface{}, error) {
    response, err := manager.platformClient.RevokeExternalTicket(ticketID, revokeData)
    if err != nil {
        return nil, err
    }
    return response, nil
}
