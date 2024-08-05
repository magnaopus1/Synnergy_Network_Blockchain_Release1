// Package management provides functionalities and services for managing the Synnergy Network blockchain,
// including state compression for efficient storage and transmission of blockchain state data.
package management

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/synnergy_network/pkg/synnergy_network/sidechains/node"
)

// StateCompressionManager manages state compression and decompression for the Synnergy Network blockchain
type StateCompressionManager struct {
	compressionMethod string
}

// NewStateCompressionManager creates a new StateCompressionManager
func NewStateCompressionManager(method string) *StateCompressionManager {
	return &StateCompressionManager{
		compressionMethod: method,
	}
}

// CompressState compresses the given state data using the specified compression method
func (scm *StateCompressionManager) CompressState(stateData interface{}) ([]byte, error) {
	var compressedData bytes.Buffer

	switch scm.compressionMethod {
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
		return nil, fmt.Errorf("unsupported compression method: %s", scm.compressionMethod)
	}

	return compressedData.Bytes(), nil
}

// DecompressState decompresses the given compressed data using the specified compression method
func (scm *StateCompressionManager) DecompressState(compressedData []byte) (interface{}, error) {
	var stateData interface{}
	reader := bytes.NewReader(compressedData)

	switch scm.compressionMethod {
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
		return nil, fmt.Errorf("unsupported compression method: %s", scm.compressionMethod)
	}

	return stateData, nil
}

// SaveCompressedState saves the compressed state data to a file
func (scm *StateCompressionManager) SaveCompressedState(filePath string, compressedData []byte) error {
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
func (scm *StateCompressionManager) LoadCompressedState(filePath string) ([]byte, error) {
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

// Example usage
func main() {
	stateData := node.NodeState{
		NodeID:      "node1",
		Health:      "Healthy",
		LastUpdated: time.Now(),
	}

	scm := NewStateCompressionManager("gzip")

	compressedData, err := scm.CompressState(stateData)
	if err != nil {
		log.Fatalf("Failed to compress state data: %v", err)
	}

	filePath := "compressed_state.gz"
	if err := scm.SaveCompressedState(filePath, compressedData); err != nil {
		log.Fatalf("Failed to save compressed state data: %v", err)
	}

	loadedData, err := scm.LoadCompressedState(filePath)
	if err != nil {
		log.Fatalf("Failed to load compressed state data: %v", err)
	}

	decompressedData, err := scm.DecompressState(loadedData)
	if err != nil {
		log.Fatalf("Failed to decompress state data: %v", err)
	}

	fmt.Printf("Decompressed State Data: %+v\n", decompressedData)
}
