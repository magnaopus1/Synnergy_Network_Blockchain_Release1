package network_util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/argon2"
)

// NetworkUtil provides utilities for network operations
type NetworkUtil struct {
	client *http.Client
}

// NewNetworkUtil creates a new NetworkUtil instance with a custom HTTP client
func NewNetworkUtil() *NetworkUtil {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	return &NetworkUtil{
		client: client,
	}
}

// Get makes a GET request to the specified URL and returns the response body
func (n *NetworkUtil) Get(url string) ([]byte, error) {
	resp, err := n.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make GET request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return body, nil
}

// Post makes a POST request to the specified URL with the given body and returns the response body
func (n *NetworkUtil) Post(url string, contentType string, body []byte) ([]byte, error) {
	resp, err := n.client.Post(url, contentType, ioutil.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to make POST request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return respBody, nil
}

// SecureConnect establishes a secure connection to the specified address using TLS
func (n *NetworkUtil) SecureConnect(address string) (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to establish secure connection: %v", err)
	}

	return conn, nil
}

// EncryptData encrypts data using Argon2 and returns the encrypted data
func (n *NetworkUtil) EncryptData(password, salt, data []byte) ([]byte, error) {
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

// DecryptData decrypts data using Argon2 and returns the decrypted data
func (n *NetworkUtil) DecryptData(password, salt, encryptedData []byte) ([]byte, error) {
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return data, nil
}

// PingServer pings a server to check its availability
func (n *NetworkUtil) PingServer(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		log.Printf("Server at %s is not reachable: %v", address, err)
		return false
	}
	conn.Close()
	return true
}

// ResolveDomain resolves a domain name to an IP address
func (n *NetworkUtil) ResolveDomain(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve domain: %v", err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain: %s", domain)
	}
	return ips[0].String(), nil
}
