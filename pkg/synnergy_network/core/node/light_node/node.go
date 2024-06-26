package light_node

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "sync"

    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/rpc"
)

const (
    blockHeadersFile = "block_headers.json"
    certFile         = "cert.pem"
    keyFile          = "key.pem"
    caCertFile       = "ca_cert.pem"
)

type BlockHeader struct {
    Height    int64  `json:"height"`
    Hash      string `json:"hash"`
    PrevHash  string `json:"prev_hash"`
    Timestamp int64  `json:"timestamp"`
}

type LightNode struct {
    mu           sync.Mutex
    blockHeaders []BlockHeader
    rpcClient    *rpc.Client
}

func NewLightNode() (*LightNode, error) {
    rpcClient, err := rpc.Dial("https://fullnode.synthron.io")
    if err != nil {
        return nil, fmt.Errorf("failed to connect to full node: %v", err)
    }

    ln := &LightNode{
        blockHeaders: []BlockHeader{},
        rpcClient:    rpcClient,
    }

    if err := ln.loadBlockHeaders(); err != nil {
        return nil, err
    }

    return ln, nil
}

func (ln *LightNode) loadBlockHeaders() error {
    ln.mu.Lock()
    defer ln.mu.Unlock()

    if _, err := os.Stat(blockHeadersFile); os.IsNotExist(err) {
        return nil // No existing headers, start fresh
    }

    data, err := ioutil.ReadFile(blockHeadersFile)
    if err != nil {
        return fmt.Errorf("failed to read block headers file: %v", err)
    }

    if err := json.Unmarshal(data, &ln.blockHeaders); err != nil {
        return fmt.Errorf("failed to unmarshal block headers: %v", err)
    }

    return nil
}

func (ln *LightNode) saveBlockHeaders() error {
    ln.mu.Lock()
    defer ln.mu.Unlock()

    data, err := json.Marshal(ln.blockHeaders)
    if err != nil {
        return fmt.Errorf("failed to marshal block headers: %v", err)
    }

    if err := ioutil.WriteFile(blockHeadersFile, data, 0644); err != nil {
        return fmt.Errorf("failed to write block headers file: %v", err)
    }

    return nil
}

func (ln *LightNode) syncBlockHeaders() error {
    var latestBlockHeader BlockHeader
    err := ln.rpcClient.Call(&latestBlockHeader, "eth_getBlockByNumber", "latest", false)
    if err != nil {
        return fmt.Errorf("failed to get latest block header: %v", err)
    }

    ln.mu.Lock()
    if len(ln.blockHeaders) == 0 || ln.blockHeaders[len(ln.blockHeaders)-1].Hash != latestBlockHeader.Hash {
        ln.blockHeaders = append(ln.blockHeaders, latestBlockHeader)
    }
    ln.mu.Unlock()

    return ln.saveBlockHeaders()
}

func (ln *LightNode) verifyTransaction(txHash string) (bool, error) {
    var receipt map[string]interface{}
    err := ln.rpcClient.Call(&receipt, "eth_getTransactionReceipt", txHash)
    if err != nil {
        return false, fmt.Errorf("failed to get transaction receipt: %v", err)
    }

    blockHash := receipt["blockHash"].(string)

    ln.mu.Lock()
    defer ln.mu.Unlock()

    for _, header := range ln.blockHeaders {
        if header.Hash == blockHash {
            return true, nil
        }
    }

    return false, nil
}

func (ln *LightNode) requestTransactionData(txHash string) (map[string]interface{}, error) {
    var txData map[string]interface{}
    err := ln.rpcClient.Call(&txData, "eth_getTransactionByHash", txHash)
    if err != nil {
        return nil, fmt.Errorf("failed to get transaction data: %v", err)
    }

    return txData, nil
}

func loadTLSConfig() (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load key pair: %v", err)
    }

    caCert, err := ioutil.ReadFile(caCertFile)
    if err != nil {
        return nil, fmt.Errorf("failed to read CA cert file: %v", err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS12,
    }, nil
}

func main() {
    lightNode, err := NewLightNode()
    if err != nil {
        log.Fatalf("Failed to create light node: %v", err)
    }

    tlsConfig, err := loadTLSConfig()
    if err != nil {
        log.Fatalf("Failed to load TLS configuration: %v", err)
    }

    server := &http.Server{
        Addr:      ":8080",
        TLSConfig: tlsConfig,
    }

    http.HandleFunc("/sync", func(w http.ResponseWriter, r *http.Request) {
        if err := lightNode.syncBlockHeaders(); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        fmt.Fprintln(w, "Block headers synchronized successfully")
    })

    http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
        txHash := r.URL.Query().Get("tx")
        if txHash == "" {
            http.Error(w, "Transaction hash required", http.StatusBadRequest)
            return
        }

        verified, err := lightNode.verifyTransaction(txHash)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        if verified {
            fmt.Fprintln(w, "Transaction verified")
        } else {
            fmt.Fprintln(w, "Transaction not verified")
        }
    })

    log.Println("Starting light node server on :8080")
    if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
