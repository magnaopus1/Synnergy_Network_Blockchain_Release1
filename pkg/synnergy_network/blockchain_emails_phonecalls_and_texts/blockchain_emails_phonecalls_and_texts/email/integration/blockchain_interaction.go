package integration

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io/ioutil"
    "net/http"
    "time"

    "golang.org/x/crypto/ripemd160"
)

// BlockchainClient is the interface for interacting with the blockchain
type BlockchainClient interface {
    SendTransaction(transaction string) (string, error)
    GetTransaction(transactionID string) (string, error)
    GetBlock(blockID string) (string, error)
}

// HttpBlockchainClient implements BlockchainClient using HTTP
type HttpBlockchainClient struct {
    baseURL string
    apiKey  string
    client  *http.Client
}

// NewHttpBlockchainClient creates a new HttpBlockchainClient
func NewHttpBlockchainClient(baseURL, apiKey string) *HttpBlockchainClient {
    return &HttpBlockchainClient{
        baseURL: baseURL,
        apiKey:  apiKey,
        client: &http.Client{
            Timeout: time.Second * 10,
        },
    }
}

// SendTransaction sends a transaction to the blockchain
func (h *HttpBlockchainClient) SendTransaction(transaction string) (string, error) {
    url := fmt.Sprintf("%s/transactions", h.baseURL)
    req, err := http.NewRequest("POST", url, nil)
    if err != nil {
        return "", err
    }

    req.Header.Set("Authorization", "Bearer "+h.apiKey)
    req.Header.Set("Content-Type", "application/json")

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

    return string(body), nil
}

// GetTransaction retrieves a transaction by its ID
func (h *HttpBlockchainClient) GetTransaction(transactionID string) (string, error) {
    url := fmt.Sprintf("%s/transactions/%s", h.baseURL, transactionID)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return "", err
    }

    req.Header.Set("Authorization", "Bearer "+h.apiKey)

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

    return string(body), nil
}

// GetBlock retrieves a block by its ID
func (h *HttpBlockchainClient) GetBlock(blockID string) (string, error) {
    url := fmt.Sprintf("%s/blocks/%s", h.baseURL, blockID)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return "", err
    }

    req.Header.Set("Authorization", "Bearer "+h.apiKey)

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

    return string(body), nil
}

// Hashing utility functions

// HashSHA256 hashes a string using SHA256
func HashSHA256(data string) string {
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// HashRIPEMD160 hashes a string using RIPEMD160
func HashRIPEMD160(data string) string {
    hasher := ripemd160.New()
    hasher.Write([]byte(data))
    hash := hasher.Sum(nil)
    return hex.EncodeToString(hash)
}
