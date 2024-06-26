package crosschainoracles

import (
	"crypto/tls"
	"net/http"
	"time"
)

// HttpClientManager manages the HTTP client configurations and requests for the cross-chain oracles.
type HttpClientManager struct {
	client *http.Client
}

// NewHttpClientManager creates a new HTTP client with custom settings for secure and efficient data fetching.
func NewHttpClientManager() *HttpClientManager {
	// Custom transport settings to manage SSL/TLS configuration and other optimizations.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Set to true to reject any SSL certificate that cannot be validated.
			InsecureSkipVerify: false,
		},
		// Max idle connections to keep open to a host.
		MaxIdleConns: 100,
		// Idle connection timeout duration.
		IdleConnTimeout: 90 * time.Second,
		// Duration to wait for the TLS handshake.
		TLSHandshakeTimeout: 10 * time.Second,
		// Enable HTTP/2.
		ForceAttemptHTTP2: true,
	}

	return &HttpClientManager{
		client: &http.Client{
			Timeout:   time.Second * 30, // Timeout for the HTTP request
			Transport: transport,
		},
	}
}

// FetchData makes an HTTP GET request to the specified URL and returns the response body.
func (m *HttpClientManager) FetchData(url string) ([]byte, error) {
	resp, err := m.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: HTTP %d %s", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// Example usage
func main() {
	manager := NewHttpClientManager()
	url := "https://api.example.com/data"
	data, err := manager.FetchData(url)
	if err != nil {
		log.Fatalf("Error fetching data: %s", err)
	}

	fmt.Printf("Data retrieved: %s\n", string(data))
}
