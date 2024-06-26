package integration_node

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "log"
    "math/big"
    "net/http"
    "sync"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "github.com/spf13/viper"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// IntegrationNode struct represents the node
type IntegrationNode struct {
    PrivateKey    *rsa.PrivateKey
    PublicKey     *rsa.PublicKey
    APIEndpoints  map[string]string
    ChainAdapters map[string]ChainAdapter
    Oracles       map[string]SmartContractOracle
    sync.RWMutex
}

// ChainAdapter interface defines methods for cross-chain communication
type ChainAdapter interface {
    Connect() error
    SendTransaction(tx interface{}) error
    FetchData(query string) (interface{}, error)
}

// SmartContractOracle interface for smart contract oracles
type SmartContractOracle interface {
    FetchData(endpoint string) (interface{}, error)
}

// NewIntegrationNode initializes a new integration node
func NewIntegrationNode() (*IntegrationNode, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    publicKey := &privateKey.PublicKey

    return &IntegrationNode{
        PrivateKey:    privateKey,
        PublicKey:     publicKey,
        APIEndpoints:  make(map[string]string),
        ChainAdapters: make(map[string]ChainAdapter),
        Oracles:       make(map[string]SmartContractOracle),
    }, nil
}

// EncryptData encrypts data using the node's public key
func (node *IntegrationNode) EncryptData(data []byte) ([]byte, error) {
    encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, node.PublicKey, data, nil)
    if err != nil {
        return nil, err
    }
    return encryptedData, nil
}

// DecryptData decrypts data using the node's private key
func (node *IntegrationNode) DecryptData(encryptedData []byte) ([]byte, error) {
    decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, node.PrivateKey, encryptedData, nil)
    if err != nil {
        return nil, err
    }
    return decryptedData, nil
}

// SignData signs data using the node's private key
func (node *IntegrationNode) SignData(data []byte) ([]byte, error) {
    hashed := sha256.Sum256(data)
    signature, err := rsa.SignPSS(rand.Reader, node.PrivateKey, crypto.SHA256, hashed[:], nil)
    if err != nil {
        return nil, err
    }
    return signature, nil
}

// VerifySignature verifies a signature using the node's public key
func (node *IntegrationNode) VerifySignature(data, signature []byte) error {
    hashed := sha256.Sum256(data)
    err := rsa.VerifyPSS(node.PublicKey, crypto.SHA256, hashed[:], signature, nil)
    if err != nil {
        return err
    }
    return nil
}

// GenerateJWT generates a JWT token
func (node *IntegrationNode) GenerateJWT(claims jwt.MapClaims) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    tokenString, err := token.SignedString(node.PrivateKey)
    if err != nil {
        return "", err
    }
    return tokenString, nil
}

// ValidateJWT validates a JWT token
func (node *IntegrationNode) ValidateJWT(tokenString string) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return node.PublicKey, nil
    })
    if err != nil {
        return nil, err
    }
    if !token.Valid {
        return nil, errors.New("invalid token")
    }
    return token, nil
}

// AddAPIEndpoint adds a new API endpoint
func (node *IntegrationNode) AddAPIEndpoint(name, url string) {
    node.Lock()
    defer node.Unlock()
    node.APIEndpoints[name] = url
}

// RemoveAPIEndpoint removes an API endpoint
func (node *IntegrationNode) RemoveAPIEndpoint(name string) {
    node.Lock()
    defer node.Unlock()
    delete(node.APIEndpoints, name)
}

// AddChainAdapter adds a new chain adapter
func (node *IntegrationNode) AddChainAdapter(name string, adapter ChainAdapter) {
    node.Lock()
    defer node.Unlock()
    node.ChainAdapters[name] = adapter
}

// RemoveChainAdapter removes a chain adapter
func (node *IntegrationNode) RemoveChainAdapter(name string) {
    node.Lock()
    defer node.Unlock()
    delete(node.ChainAdapters, name)
}

// AddOracle adds a new smart contract oracle
func (node *IntegrationNode) AddOracle(name string, oracle SmartContractOracle) {
    node.Lock()
    defer node.Unlock()
    node.Oracles[name] = oracle
}

// RemoveOracle removes a smart contract oracle
func (node *IntegrationNode) RemoveOracle(name string) {
    node.Lock()
    defer node.Unlock()
    delete(node.Oracles, name)
}

// HealthCheck performs a health check on the node
func (node *IntegrationNode) HealthCheck() error {
    // Check API endpoints
    node.RLock()
    for name, url := range node.APIEndpoints {
        resp, err := http.Get(url)
        if err != nil || resp.StatusCode != http.StatusOK {
            node.RUnlock()
            return fmt.Errorf("API endpoint %s is down", name)
        }
    }
    node.RUnlock()

    // Check chain adapters
    node.RLock()
    for name, adapter := range node.ChainAdapters {
        if err := adapter.Connect(); err != nil {
            node.RUnlock()
            return fmt.Errorf("chain adapter %s is down", name)
        }
    }
    node.RUnlock()

    // Check oracles
    node.RLock()
    for name, oracle := range node.Oracles {
        if _, err := oracle.FetchData(""); err != nil {
            node.RUnlock()
            return fmt.Errorf("oracle %s is down", name)
        }
    }
    node.RUnlock()

    return nil
}

// Run starts the integration node
func (node *IntegrationNode) Run(ctx context.Context) error {
    r := mux.NewRouter()
    r.HandleFunc("/health", node.HealthHandler).Methods("GET")
    srv := &http.Server{
        Addr:    ":8080",
        Handler: r,
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen: %s\n", err)
        }
    }()
    log.Println("Integration Node is running at :8080")

    <-ctx.Done()
    log.Println("Shutting down the server...")

    ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if err := srv.Shutdown(ctxShutDown); err != nil {
        return fmt.Errorf("server Shutdown Failed:%+v", err)
    }
    log.Println("Server exited properly")
    return nil
}

// HealthHandler handles the health check endpoint
func (node *IntegrationNode) HealthHandler(w http.ResponseWriter, r *http.Request) {
    if err := node.HealthCheck(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

// Argon2HashPassword hashes a password using Argon2
func Argon2HashPassword(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// ScryptHashPassword hashes a password using Scrypt
func ScryptHashPassword(password, salt []byte) ([]byte, error) {
    return scrypt.Key(password, salt, 1<<15, 8, 1, 32)
}

// GenerateSalt generates a new salt
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }
    return salt, nil
}
