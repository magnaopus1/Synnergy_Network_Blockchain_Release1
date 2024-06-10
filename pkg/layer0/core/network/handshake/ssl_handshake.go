package handshake

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
)

// LoadCertificates loads client and server certificates along with their respective private keys.
func LoadCertificates(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// SetupTLSConfig prepares the TLS configuration with the necessary certificates and security settings.
func SetupTLSConfig(certificates []tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:       certificates,
		InsecureSkipVerify: true, // Note: Set to false in production
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		PreferServerCipherSuites: true,
	}
}

// StartTLSServer initializes a TLS server on the specified port and handles client connections securely.
func StartTLSServer(config *tls.Config, port string) {
	listener, err := tls.Listen("tcp", ":"+port, config)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()
	log.Printf("Server listening on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleClient(conn)
	}
}

// handleClient manages the client connection for data transmission over a secure channel.
func handleClient(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 512)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Error reading from client: %v", err)
			return
		}
		log.Printf("Received: %s", string(buffer[:n]))
	}
}

func main() {
	serverCert, err := LoadCertificates("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Error loading certificates: %v", err)
	}

	clientCert, err := LoadCertificates("client.crt", "client.key")
	if err != nil {
		log.Fatalf("Error loading certificates: %v", err)
	}

	tlsConfig := SetupTLSConfig([]tls.Certificate{serverCert, clientCert})
	StartTLSServer(tlsConfig, "8443")
}
