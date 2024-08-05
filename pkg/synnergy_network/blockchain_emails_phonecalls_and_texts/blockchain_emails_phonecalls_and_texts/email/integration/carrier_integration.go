package integration

import (
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "time"
)

// CarrierClient is the interface for interacting with carrier services
type CarrierClient interface {
    SendMessage(to string, message string) (string, error)
    CheckBalance() (float64, error)
}

// HttpCarrierClient implements CarrierClient using HTTP
type HttpCarrierClient struct {
    baseURL    string
    apiKey     string
    client     *http.Client
    senderName string
}

// NewHttpCarrierClient creates a new HttpCarrierClient
func NewHttpCarrierClient(baseURL, apiKey, senderName string) *HttpCarrierClient {
    return &HttpCarrierClient{
        baseURL: baseURL,
        apiKey:  apiKey,
        client: &http.Client{
            Timeout: time.Second * 10,
        },
        senderName: senderName,
    }
}

// SendMessage sends a message through the carrier service
func (h *HttpCarrierClient) SendMessage(to, message string) (string, error) {
    form := url.Values{}
    form.Add("to", to)
    form.Add("message", message)
    form.Add("sender", h.senderName)

    req, err := http.NewRequest("POST", fmt.Sprintf("%s/send", h.baseURL), nil)
    if err != nil {
        return "", err
    }
    
    req.URL.RawQuery = form.Encode()
    req.Header.Set("Authorization", "Bearer "+h.apiKey)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := h.client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    if resp.StatusCode != http.StatusOK {
        return "", errors.New(string(body))
    }

    var result map[string]interface{}
    if err := json.Unmarshal(body, &result); err != nil {
        return "", err
    }

    return result["message_id"].(string), nil
}

// CheckBalance checks the account balance of the carrier service
func (h *HttpCarrierClient) CheckBalance() (float64, error) {
    req, err := http.NewRequest("GET", fmt.Sprintf("%s/balance", h.baseURL), nil)
    if err != nil {
        return 0, err
    }

    req.Header.Set("Authorization", "Bearer "+h.apiKey)

    resp, err := h.client.Do(req)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return 0, err
    }

    if resp.StatusCode != http.StatusOK {
        return 0, errors.New(string(body))
    }

    var result map[string]interface{}
    if err := json.Unmarshal(body, &result); err != nil {
        return 0, err
    }

    balance, ok := result["balance"].(float64)
    if !ok {
        return 0, errors.New("invalid balance format")
    }

    return balance, nil
}
