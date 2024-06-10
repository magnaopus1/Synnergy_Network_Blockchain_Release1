package server

import (
    "net/http"
    "crypto/tls"
    "time"
    "log"

    "github.com/synthron_blockchain_final/pkg/layer0/core/blockchain"
    "github.com/synthron_blockchain_final/pkg/layer0/core/network/security"
)

// MiddlewareManager configures and manages all middleware for the server.
type MiddlewareManager struct {
    Blockchain *blockchain.Blockchain
    SecurityManager *security.SecurityManager
}

// NewMiddlewareManager creates a new instance of MiddlewareManager.
func NewMiddlewareManager(bc *blockchain.Blockchain, secManager *security.SecurityManager) *MiddlewareManager {
    return &MiddlewareManager{
        Blockchain: bc,
        SecurityManager: secManager,
    }
}

// SetupHTTPServer initializes and configures the HTTP server.
func (m *MiddlewareManager) SetupHTTPServer(port string) {
    srv := &http.Server{
        Addr:         ":" + port,
        Handler:      m.setupRoutes(),
        TLSConfig:    m.getTLSConfig(),
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  15 * time.Second,
    }

    log.Println("Starting HTTP Server on port", port)
    if err := srv.ListenAndServeTLS("", ""); err != nil {
        log.Fatalf("Failed to start HTTP server: %v", err)
    }
}

// setupRoutes configures the routing for the server.
func (m *MiddlewareManager) setupRoutes() http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/transaction", m.handleTransaction)
    mux.HandleFunc("/api/block", m.handleBlock)
    return mux
}

// handleTransaction processes transactions through the server.
func (m *MiddlewareManager) handleTransaction(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
        return
    }
    // Transaction processing logic here
}

// handleBlock processes blocks through the server.
func (m *MiddlewareManager) handleBlock(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
        return
    }
    // Block processing logic here
}

// getTLSConfig returns the TLS configuration for secure communications.
func (m *MiddlewareManager) get![](https://)TLSConfig() *tls.Config {
    return &tls.Config{
        // Recommended TLS settings for security
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }
}

