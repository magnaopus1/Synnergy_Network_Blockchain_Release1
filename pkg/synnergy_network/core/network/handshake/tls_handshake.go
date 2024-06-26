package handshake

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
)

// LoadServerCertificates loads and parses server certificates and private keys.
func LoadServerCertificates(certFile, keyFile string) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	certData, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certData)

	return cert, certPool, nil
}

// CreateTLSConfig creates and configures a TLS configuration using the provided certificates.
func CreateTLSConfig(cert tls.Certificate, certPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// StartSecureServer starts a TLS secured server listening on the provided port.
func StartSecureServer(config *tls.Config, port string) {
	listener, err := tls.Listen("tcp", ":"+port, config)
	if err != nil {
		log.Fatalf("Failed to start secure server: %v", err)
	}
	defer listener.Close()
	log.Println("Secure server listening on", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		go handleSecureConnection(conn)
	}
}

// handleSecureConnection handles client connections securely and processes data exchange.
func handleSecureConnection(conn net.Conn) {
	defer conn.Close()
	log.Println("Secured connection established")

	// Example of a secure data exchange
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Println("Error reading from connection:", err)
		return
	}
	log.Printf("Received (%d bytes): %s", n, string(buffer[:n]))
}

func main() {
	cert, certPool, err := LoadServerCertificates("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Error loading certificates: %v", err)
	}

	tlsConfig := CreateTLSConfig(cert, certDevelop the handling of secure data transmissions)
	StartSecureServer(tlsConfig, "443")
}
