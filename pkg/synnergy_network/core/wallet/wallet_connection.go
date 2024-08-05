package wallet_connection

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain/network/rpc"
	"github.com/synnergy_network/blockchain/network/utils"
)

// RPCNetworkManager manages RPC network connections for the wallet
type RPCNetworkManager struct {
	currentNetwork string
	networks       map[string]*rpc.RPCClient
	mu             sync.Mutex
	logger         *utils.Logger
}

// NewRPCNetworkManager initializes a new RPCNetworkManager instance
func NewRPCNetworkManager(logger *utils.Logger) *RPCNetworkManager {
	return &RPCNetworkManager{
		networks: make(map[string]*rpc.RPCClient),
		logger:   logger,
	}
}

// AddNetwork adds a new RPC network to the manager
func (m *RPCNetworkManager) AddNetwork(name string, client *rpc.RPCClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.networks[name] = client
	m.logger.Info("Added new RPC network: " + name)
}

// RemoveNetwork removes an RPC network from the manager
func (m *RPCNetworkManager) RemoveNetwork(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.networks[name]; !exists {
		return errors.New("network not found")
	}
	delete(m.networks, name)
	m.logger.Info("Removed RPC network: " + name)
	return nil
}

// SwitchNetwork changes the current RPC network
func (m *RPCNetworkManager) SwitchNetwork(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, exists := m.networks[name]
	if !exists {
		return errors.New("network not found")
	}
	m.currentNetwork = name
	m.logger.Info("Switched to RPC network: " + name)
	go m.monitorConnection(client)
	return nil
}

// GetCurrentNetwork returns the name of the current RPC network
func (m *RPCNetworkManager) GetCurrentNetwork() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentNetwork
}

// monitorConnection monitors the connection to the RPC network and attempts reconnection if needed
func (m *RPCNetworkManager) monitorConnection(client *rpc.RPCClient) {
	for {
		err := client.Ping()
		if err != nil {
			m.logger.Warning("Lost connection to RPC network, attempting to reconnect...")
			for {
				time.Sleep(5 * time.Second)
				err := client.Reconnect()
				if err == nil {
					m.logger.Info("Reconnected to RPC network")
					break
				}
				m.logger.Error("Reconnection attempt failed: " + err.Error())
			}
		}
		time.Sleep(30 * time.Second)
	}
}
package wallet_connection

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/logger"
	"github.com/synnergy_network/blockchain/network"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/blockchain/utils"
)

// RPCNetworkConnection represents a connection to an RPC network.
type RPCNetworkConnection struct {
	mu           sync.Mutex
	client       *http.Client
	baseURL      string
	token        string
	networkState *network.State
	logger       *logger.Logger
	security     *security.SecurityManager
}

// NewRPCNetworkConnection initializes a new RPC network connection.
func NewRPCNetworkConnection(baseURL, token string, insecureSkipVerify bool) *RPCNetworkConnection {
	// Set up a custom HTTP client with TLS configuration
	tlsConfig := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	logger := logger.NewLogger("logs/rpc_network_connection.log", []string{logger.INFO, logger.ERROR, logger.FATAL})

	return &RPCNetworkConnection{
		client:  client,
		baseURL: baseURL,
		token:   token,
		logger:  logger,
		security: security.NewSecurityManager(),
		networkState: network.NewState(),
	}
}

// makeRequest creates and sends an HTTP request to the RPC server.
func (conn *RPCNetworkConnection) makeRequest(ctx context.Context, endpoint string, method string, payload interface{}) ([]byte, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Serialize the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		conn.logger.Error("Error marshalling payload: " + err.Error())
		return nil, err
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, method, conn.baseURL+endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		conn.logger.Error("Error creating request: " + err.Error())
		return nil, err
	}

	// Add authentication token
	req.Header.Add("Authorization", "Bearer "+conn.token)
	req.Header.Add("Content-Type", "application/json")

	// Send the request
	resp, err := conn.client.Do(req)
	if err != nil {
		conn.logger.Error("Error sending request: " + err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		conn.logger.Error("Error reading response body: " + err.Error())
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		conn.logger.Error("Non-OK HTTP status: " + resp.Status)
		return nil, errors.New("non-OK HTTP status: " + resp.Status)
	}

	return respBody, nil
}

// Connect initializes the connection to the RPC network.
func (conn *RPCNetworkConnection) Connect() error {
	conn.logger.Info("Connecting to RPC network at " + conn.baseURL)

	// Example of a connect endpoint, this can vary based on the RPC server implementation
	respBody, err := conn.makeRequest(context.Background(), "/connect", "POST", nil)
	if err != nil {
		conn.logger.Error("Failed to connect to RPC network: " + err.Error())
		return err
	}

	// Parse and log the connection response
	var connectResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &connectResponse); err != nil {
		conn.logger.Error("Failed to parse connect response: " + err.Error())
		return err
	}

	conn.logger.Info("Successfully connected to RPC network")
	return nil
}

// Disconnect closes the connection to the RPC network.
func (conn *RPCNetworkConnection) Disconnect() error {
	conn.logger.Info("Disconnecting from RPC network at " + conn.baseURL)

	// Example of a disconnect endpoint, this can vary based on the RPC server implementation
	_, err := conn.makeRequest(context.Background(), "/disconnect", "POST", nil)
	if err != nil {
		conn.logger.Error("Failed to disconnect from RPC network: " + err.Error())
		return err
	}

	conn.logger.Info("Successfully disconnected from RPC network")
	return nil
}

// SendTransaction sends a transaction to the RPC network.
func (conn *RPCNetworkConnection) SendTransaction(transaction *crypto.Transaction) error {
	conn.logger.Info("Sending transaction to RPC network")

	// Encrypt the transaction before sending
	encryptedTransaction, err := conn.security.EncryptTransaction(transaction)
	if err != nil {
		conn.logger.Error("Error encrypting transaction: " + err.Error())
		return err
	}

	// Send the encrypted transaction to the network
	_, err = conn.makeRequest(context.Background(), "/sendTransaction", "POST", encryptedTransaction)
	if err != nil {
		conn.logger.Error("Failed to send transaction: " + err.Error())
		return err
	}

	conn.logger.Info("Transaction sent successfully")
	return nil
}

// GetTransactionStatus retrieves the status of a transaction from the RPC network.
func (conn *RPCNetworkConnection) GetTransactionStatus(transactionID string) (*crypto.TransactionStatus, error) {
	conn.logger.Info("Getting transaction status for ID: " + transactionID)

	// Make the request to get transaction status
	respBody, err := conn.makeRequest(context.Background(), "/transactionStatus", "POST", map[string]string{"transactionID": transactionID})
	if err != nil {
		conn.logger.Error("Failed to get transaction status: " + err.Error())
		return nil, err
	}

	// Parse the response
	var status crypto.TransactionStatus
	if err := json.Unmarshal(respBody, &status); err != nil {
		conn.logger.Error("Failed to parse transaction status response: " + err.Error())
		return nil, err
	}

	conn.logger.Info("Transaction status retrieved successfully")
	return &status, nil
}

// ChangeNetwork allows for changing the RPC network URL and token.
func (conn *RPCNetworkConnection) ChangeNetwork(newBaseURL, newToken string) {
	conn.logger.Info("Changing RPC network to " + newBaseURL)

	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.baseURL = newBaseURL
	conn.token = newToken

	conn.logger.Info("RPC network changed successfully")
}

// MonitorNetworkState monitors the state of the network for changes.
func (conn *RPCNetworkConnection) MonitorNetworkState(ctx context.Context, interval time.Duration) {
	conn.logger.Info("Starting network state monitoring")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			conn.logger.Info("Checking network state")
			// Example of an endpoint to get network state, this can vary based on the RPC server implementation
			respBody, err := conn.makeRequest(ctx, "/networkState", "GET", nil)
			if err != nil {
				conn.logger.Error("Failed to get network state: " + err.Error())
				continue
			}

			// Parse and log the network state
			var state network.State
			if err := json.Unmarshal(respBody, &state); err != nil {
				conn.logger.Error("Failed to parse network state response: " + err.Error())
				continue
			}

			conn.networkState = &state
			conn.logger.Info("Network state updated successfully")

		case <-ctx.Done():
			conn.logger.Info("Stopping network state monitoring")
			return
		}
	}
}
package wallet_connection

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "net/http"
    "sync"
    "time"

    "github.com/synnergy_network/blockchain/utils"
    "github.com/synnergy_network/blockchain/logger"
    "github.com/synnergy_network/blockchain/crypto"
)

// RPCConnection represents the connection to the RPC network
type RPCConnection struct {
    Endpoint   string
    Client     *http.Client
    Mu         sync.Mutex
    IsConnected bool
}

// NewRPCConnection initializes a new RPCConnection instance
func NewRPCConnection(endpoint string) *RPCConnection {
    return &RPCConnection{
        Endpoint: endpoint,
        Client: &http.Client{
            Timeout: 30 * time.Second,
        },
        IsConnected: false,
    }
}

// EncryptData encrypts the given data using AES encryption
func EncryptData(data, passphrase string) (string, error) {
    key := sha256.Sum256([]byte(passphrase))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given data using AES encryption
func DecryptData(data, passphrase string) (string, error) {
    key := sha256.Sum256([]byte(passphrase))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    ciphertext, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// Connect establishes a connection to the RPC network
func (rpc *RPCConnection) Connect() error {
    rpc.Mu.Lock()
    defer rpc.Mu.Unlock()

    if rpc.IsConnected {
        return nil
    }

    resp, err := rpc.Client.Get(rpc.Endpoint)
    if err != nil {
        logger.Error(fmt.Sprintf("Failed to connect to RPC endpoint: %s", err))
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        err := fmt.Errorf("unexpected status code: %d", resp.StatusCode)
        logger.Error(err.Error())
        return err
    }

    rpc.IsConnected = true
    logger.Info("Successfully connected to RPC endpoint")
    return nil
}

// Disconnect closes the connection to the RPC network
func (rpc *RPCConnection) Disconnect() {
    rpc.Mu.Lock()
    defer rpc.Mu.Unlock()

    rpc.IsConnected = false
    logger.Info("Disconnected from RPC endpoint")
}

// SwitchRPCNetwork switches the RPC connection to a new endpoint
func (rpc *RPCConnection) SwitchRPCNetwork(newEndpoint string) error {
    rpc.Disconnect()
    rpc.Endpoint = newEndpoint
    return rpc.Connect()
}

// SendRequest sends a request to the RPC network
func (rpc *RPCConnection) SendRequest(requestBody []byte, passphrase string) ([]byte, error) {
    if !rpc.IsConnected {
        return nil, errors.New("not connected to RPC endpoint")
    }

    encryptedRequest, err := EncryptData(string(requestBody), passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt request: %v", err)
    }

    req, err := http.NewRequest("POST", rpc.Endpoint, strings.NewReader(encryptedRequest))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := rpc.Client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    encryptedResponse, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %v", err)
    }

    decryptedResponse, err := DecryptData(string(encryptedResponse), passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt response: %v", err)
    }

    return []byte(decryptedResponse), nil
}
package wallet_connection

import (
    "fmt"
    "log"
    "sync"
    "github.com/synnergy_network/blockchain/network"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/utils"
    "github.com/synnergy_network/core/wallet/config"
    "github.com/synnergy_network/core/wallet/utils/error_handling"
    "github.com/synnergy_network/core/wallet/utils/logging"
)

// LocalConnectionManager manages the switching between different local nodes.
type LocalConnectionManager struct {
    currentNode   string
    nodes         map[string]string
    mu            sync.Mutex
    logger        *logging.Logger
    securityGuard *security.Guard
}

// NewLocalConnectionManager initializes a new LocalConnectionManager instance.
func NewLocalConnectionManager(logger *logging.Logger, securityGuard *security.Guard) *LocalConnectionManager {
    return &LocalConnectionManager{
        nodes:         make(map[string]string),
        logger:        logger,
        securityGuard: securityGuard,
    }
}

// AddNode adds a new local node to the connection manager.
func (manager *LocalConnectionManager) AddNode(alias, address string) {
    manager.mu.Lock()
    defer manager.mu.Unlock()
    manager.nodes[alias] = address
    manager.logger.Info(fmt.Sprintf("Added new node: %s at %s", alias, address))
}

// SwitchToNode switches the connection to a specified local node.
func (manager *LocalConnectionManager) SwitchToNode(alias string) error {
    manager.mu.Lock()
    defer manager.mu.Unlock()

    address, exists := manager.nodes[alias]
    if !exists {
        err := fmt.Errorf("node with alias %s not found", alias)
        manager.logger.Error(err.Error())
        return err
    }

    // Establish connection to the new node
    err := network.ConnectToLocalNode(address)
    if err != nil {
        manager.logger.Error(fmt.Sprintf("Failed to connect to node %s at %s: %v", alias, address, err))
        return err
    }

    manager.currentNode = alias
    manager.logger.Info(fmt.Sprintf("Switched to node %s at %s", alias, address))
    return nil
}

// CurrentNode returns the current active node alias.
func (manager *LocalConnectionManager) CurrentNode() string {
    manager.mu.Lock()
    defer manager.mu.Unlock()
    return manager.currentNode
}

// SecureSwitchToNode securely switches the connection to a specified local node after authentication.
func (manager *LocalConnectionManager) SecureSwitchToNode(alias, authToken string) error {
    manager.mu.Lock()
    defer manager.mu.Unlock()

    // Authenticate the action
    if !manager.securityGuard.Authenticate(authToken) {
        err := fmt.Errorf("authentication failed for switching to node %s", alias)
        manager.logger.Error(err.Error())
        return err
    }

    address, exists := manager.nodes[alias]
    if !exists {
        err := fmt.Errorf("node with alias %s not found", alias)
        manager.logger.Error(err.Error())
        return err
    }

    // Establish connection to the new node
    err := network.ConnectToLocalNode(address)
    if err != nil {
        manager.logger.Error(fmt.Sprintf("Failed to connect to node %s at %s: %v", alias, address, err))
        return err
    }

    manager.currentNode = alias
    manager.logger.Info(fmt.Sprintf("Securely switched to node %s at %s", alias, address))
    return nil
}

// DisconnectNode disconnects the current node.
func (manager *LocalConnectionManager) DisconnectNode() error {
    manager.mu.Lock()
    defer manager.mu.Unlock()

    if manager.currentNode == "" {
        err := fmt.Errorf("no active node to disconnect")
        manager.logger.Error(err.Error())
        return err
    }

    err := network.DisconnectFromLocalNode(manager.nodes[manager.currentNode])
    if err != nil {
        manager.logger.Error(fmt.Sprintf("Failed to disconnect from node %s: %v", manager.currentNode, err))
        return err
    }

    manager.logger.Info(fmt.Sprintf("Disconnected from node %s", manager.currentNode))
    manager.currentNode = ""
    return nil
}

// ListNodes lists all available nodes.
func (manager *LocalConnectionManager) ListNodes() map[string]string {
    manager.mu.Lock()
    defer manager.mu.Unlock()
    return manager.nodes
}

// SecureListNodes lists all available nodes with security check.
func (manager *LocalConnectionManager) SecureListNodes(authToken string) (map[string]string, error) {
    manager.mu.Lock()
    defer manager.mu.Unlock()

    if !manager.securityGuard.Authenticate(authToken) {
        err := fmt.Errorf("authentication failed for listing nodes")
        manager.logger.Error(err.Error())
        return nil, err
    }

    return manager.nodes, nil
}
