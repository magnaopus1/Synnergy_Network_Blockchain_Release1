package handshake

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
)

// LoadCertificates loads TLS certificates and builds an x509 certificate pool.
func LoadCertificates(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	if !certPool.AppendCertsFromPEM(data) {
		return nil, err
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          certCoonfiguration,
		RootCAs:            certPool,
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		PreferServerCipherSuites: true,
		NextProtos:         []string{"h2", "http/1.1"}, // Support for HTTP/2 and HTTP/1.1
	}, nil
}

// StartTLSServer starts a TLS server on the specified port.
func StartTLSServer(config *tls.Config, port string) {
	listener, err := tls.Listen("tcp", ":"+port, config)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %v", err)
	}
	defer listener.Close()

	log.Println("TLS server listening on port", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// handleConnection handles client connections securely.
func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Println("Secure connection established")

	// Example secure data handling
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Println("Error reading from secure connection:", err)
		return
	}
	log.Printf("Received (%d bytes): %s", n, string(buffer[:n]))
}

func main() {
	tlsConfig, err := LoadCertificates("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Error setting up TLS configuration: %v", err)
	}

	StartTLSServer(tlsConfig, "443")
}
