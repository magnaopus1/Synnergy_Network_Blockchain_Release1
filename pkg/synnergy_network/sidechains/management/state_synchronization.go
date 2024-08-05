// Package management provides functionalities and services for managing the Synnergy Network blockchain,
// including state synchronization for maintaining consistency across nodes.
package management

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/synnergy_network/pkg/synnergy_network/sidechains/node"
)

// StateSynchronizationManager manages state synchronization for the Synnergy Network blockchain
type StateSynchronizationManager struct {
	compressionMethod string
	nodes             []string
}

// NewStateSynchronizationManager creates a new StateSynchronizationManager
func NewStateSynchronizationManager(method string, nodes []string) *StateSynchronizationManager {
	return &StateSynchronizationManager{
		compressionMethod: method,
		nodes:             nodes,
	}
}

// CompressState compresses the given state data using the specified compression method
func (ssm *StateSynchronizationManager) CompressState(stateData interface{}) ([]byte, error) {
	var compressedData bytes.Buffer

	switch ssm.compressionMethod {
	case "gzip":
		writer := gzip.NewWriter(&compressedData)
		defer writer.Close()

		if err := json.NewEncoder(writer).Encode(stateData); err != nil {
			return nil, fmt.Errorf("failed to compress state data using gzip: %v", err)
		}

	case "lz4":
		writer := lz4.NewWriter(&compressedData)
		defer writer.Close()

		if err := json.NewEncoder(writer).Encode(stateData); err != nil {
			return nil, fmt.Errorf("failed to compress state data using lz4: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported compression method: %s", ssm.compressionMethod)
	}

	return compressedData.Bytes(), nil
}

// DecompressState decompresses the given compressed data using the specified compression method
func (ssm *StateSynchronizationManager) DecompressState(compressedData []byte) (interface{}, error) {
	var stateData interface{}
	reader := bytes.NewReader(compressedData)

	switch ssm.compressionMethod {
	case "gzip":
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gzipReader.Close()

		if err := json.NewDecoder(gzipReader).Decode(&stateData); err != nil {
			return nil, fmt.Errorf("failed to decompress state data using gzip: %v", err)
		}

	case "lz4":
		lz4Reader := lz4.NewReader(reader)

		if err := json.NewDecoder(lz4Reader).Decode(&stateData); err != nil {
			return nil, fmt.Errorf("failed to decompress state data using lz4: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported compression method: %s", ssm.compressionMethod)
	}

	return stateData, nil
}

// SaveCompressedState saves the compressed state data to a file
func (ssm *StateSynchronizationManager) SaveCompressedState(filePath string, compressedData []byte) error {
	hash := sha256.Sum256(compressedData)
	checksum := hash[:]

	if err := ioutil.WriteFile(filePath, compressedData, 0644); err != nil {
		return fmt.Errorf("failed to save compressed state data to file: %v", err)
	}

	if err := ioutil.WriteFile(filePath+".checksum", checksum, 0644); err != nil {
		return fmt.Errorf("failed to save checksum to file: %v", err)
	}

	return nil
}

// LoadCompressedState loads the compressed state data from a file and verifies its checksum
func (ssm *StateSynchronizationManager) LoadCompressedState(filePath string) ([]byte, error) {
	compressedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load compressed state data from file: %v", err)
	}

	checksum, err := ioutil.ReadFile(filePath + ".checksum")
	if err != nil {
		return nil, fmt.Errorf("failed to load checksum from file: %v", err)
	}

	hash := sha256.Sum256(compressedData)
	if !bytes.Equal(hash[:], checksum) {
		return nil, fmt.Errorf("checksum verification failed")
	}

	return compressedData, nil
}

// SynchronizeState synchronizes the state across all nodes in the network
func (ssm *StateSynchronizationManager) SynchronizeState(stateData interface{}) error {
	compressedData, err := ssm.CompressState(stateData)
	if err != nil {
		return fmt.Errorf("failed to compress state data: %v", err)
	}

	for _, nodeURL := range ssm.nodes {
		if err := ssm.sendStateToNode(nodeURL, compressedData); err != nil {
			log.Printf("failed to send state to node %s: %v", nodeURL, err)
		}
	}

	return nil
}

// sendStateToNode sends the compressed state data to the specified node
func (ssm *StateSynchronizationManager) sendStateToNode(nodeURL string, compressedData []byte) error {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/state_sync", nodeURL), bytes.NewReader(compressedData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to synchronize state with node %s: %s", nodeURL, string(body))
	}

	return nil
}

// Example usage
func main() {
	stateData := node.NodeState{
		NodeID:      "node1",
		Health:      "Healthy",
		LastUpdated: time.Now(),
	}

	nodes := []string{
		"http://node2.synnergy_network:8080",
		"http://node3.synnergy_network:8080",
	}

	ssm := NewStateSynchronizationManager("gzip", nodes)

	if err := ssm.SynchronizeState(stateData); err != nil {
		log.Fatalf("Failed to synchronize state: %v", err)
	}

	log.Println("State synchronized successfully")
}
