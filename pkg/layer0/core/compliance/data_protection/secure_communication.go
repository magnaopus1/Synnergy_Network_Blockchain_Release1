package data_protection

import (
    "crypto/tls"
    "crypto/x509"
    "errors"
    "io/ioutil"
    "net"
)

// SecureCommunicator provides tools to establish secure communication channels.
type SecureCommunicator struct {
    tlsConfig *tls.Config
}

// NewSecureCommunicator initializes a TLS configuration for secure communications.
func NewSecureCommunicator(certFile, keyFile string) (*SecureCommunicator, error) {
    certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }

    caCertPool := x509.NewCertPool()
    caCert, err := ioutil.ReadFile(certFile)
    if err != nil {
        return nil, err
    }

    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, errors.New("failed to append CA certificate")
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{certificate},
        RootCAs:      caCertPool,
        ClientCAs:    caCertPool,
        ClientAuth:   tls.RequireAndVerifyClientCert,
        MinVersion:   tls.VersionTLS12,
    }

    return &SecureCommunicator{
        tlsConfig: tlsConfig,
    }, nil
}

// StartSecureServer starts a secure TLS server on the specified address.
func (sc *SecureCommunicator) StartSecureServer(addr string) error {
    listener, err := tls.Listen("tcp", addr, sc.tlsConfig)
    if err != nil {
        return err
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            return err
        }
        go sc.handleConnection(conn)
    }
}

// handleConnection handles individual TLS connections for data transmission.
func (sc *SecureCommunicator) handleConnection(conn net.Conn) {
    defer conn.Close()
    // Handle the connection for data transfer, e.g., reading and writing to the conn
    // Implement logic based on specific application protocol
}

// CreateSecureClient creates a secure TLS client to communicate with a TLS server.
func (sc *SecureCommunicator) CreateSecureClient(serverAddr string) (*tls.Conn, error) {
    conn, err := tls.Dial("tcp", serverAddr, sc.tlsConfig)
    if err != nil {
        return nil, err
    }
    return conn, nil
}

