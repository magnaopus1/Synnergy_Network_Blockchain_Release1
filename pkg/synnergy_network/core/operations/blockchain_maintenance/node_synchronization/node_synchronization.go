package blockchain_maintenance

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// NodeInfo contains metadata about a blockchain node.
type NodeInfo struct {
	Height    int64  `json:"height"`
	Timestamp int64  `json:"timestamp"`
	NodeID    string `json:"node_id"`
}

// SyncPayload contains the data to synchronize between nodes.
type SyncPayload struct {
	Nodes []NodeInfo `json:"nodes"`
}

// synchronizeNodes attempts to synchronize the current node with a list of peer nodes.
func synchronizeNodes(peers []string) error {
	localInfo := getCurrentNodeInfo()
	payload := SyncPayload{
		Nodes: []NodeInfo{localInfo},
	}

	for _, peer := range peers {
		if err := sendSyncRequest(peer, payload); err != nil {
			log.Printf("Failed to synchronize with peer %s: %v", peer, err)
			continue
		}
	}

	return nil
}

// sendSyncRequest sends a synchronization request to a peer node.
func sendSyncRequest(peer string, payload SyncPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	encryptedData, err := encryptData(data)
	if err != nil {
		return err
	}

	resp, err := http.Post("http://"+peer+"/sync", "application/octet-stream", encryptedData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to sync with %s, response status: %s", peer, resp.Status)
	}

	return nil
}

// getCurrentNodeInfo retrieves the current state of the node.
func getCurrentNodeInfo() NodeInfo {
	// Placeholder for actual node info retrieval logic
	return NodeInfo{
		Height:    500000, // Example block height
		Timestamp: time.Now().Unix(),
		NodeID:    "node123",
	}
}

// encryptData encrypts data using a secure method.
func encryptData(data []byte) ([]byte, error) {
	key := []byte("the-key-has-to-be-32-bytes-long!") // Example key
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce[:aead.NonceSize()]); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, data, nil), nil
}

// Example main function to initiate synchronization with peers.
func main() {
	peers := []string{"192.168.1.1:8080", "192.168.1.2:8080"} // Example peer IPs
	if err := synchronizeNodes(peers); err != nil {
		log.Fatalf("Synchronization failed: %v", err)
	}
}
