package blockchain_compression

import (
    "bytes"
    "compress/gzip"
    "encoding/gob"
    "errors"
    "io"
    "sync"
    "log"
)

// CompressedBlock represents a block that has been compressed for storage or transmission.
type CompressedBlock struct {
    Data []byte
}

// compressData compresses blockchain data using gzip, tailored for blockchain structures.
func compressData(data []byte) ([]byte, error) {
    var buf bytes.Buffer
    gzipWriter := gzip.NewWriter(&buf)
    if _, err := gzipWriter.Write(data); err != nil {
        return nil, err
    }
    if err := gzipWriter.Close(); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

// decompressData decompresses blockchain data.
func decompressData(data []byte) ([]byte, error) {
    buf := bytes.NewBuffer(data)
    gzipReader, err := gzip.NewReader(buf)
    if err != nil {
        return nil, err
    }
    decompressedData, err := io.ReadAll(gzipReader)
    if err != nil {
        return nil, err
    }
    if err := gzipReader.Close(); err != nil {
        return nil, err
    }
    return decompressedData, nil
}

// PruneBlockchain selectively removes obsolete data from the blockchain storage.
func PruneBlockchain(chain *Blockchain) error {
    // Example logic to prune data older than a certain threshold or flagged as removable
    var newBlocks []Block
    for _, block := range chain.Blocks {
        if block.Timestamp > time.Now().AddDate(0, -6, 0).Unix() { // Keeps blocks from the last 6 months only
            newBlocks = append(newBlocks, block)
        }
    }
    chain.Blocks = newBlocks
    return nil
}


// SyncDifferential synchronizes blockchain data using differential updates.
func SyncDifferential(base, update []byte) ([]byte, error) {
    baseData := make(map[string]interface{})
    updateData := make(map[string]interface{})
    
    // Decoding data for manipulation (assuming data is in a suitable format)
    if err := DecodeFromGob(base, &baseData); err != nil {
        return nil, err
    }
    if err := DecodeFromGob(update, &updateData); err != nil {
        return nil, err
    }

    // Applying differential updates
    for key, value := range updateData {
        baseData[key] = value // This simplistic approach can be expanded with more complex merging logic
    }

    // Encoding data back after applying updates
    result, err := EncodeToGob(baseData)
    if err != nil {
        return nil, err
    }

    return result, nil
}


// AdaptiveCompression adjusts the compression level based on network conditions.
func AdaptiveCompression(currentLoad int) int {
    // Example: Adjust compression based on the current network traffic and node capabilities
    if currentLoad > 80 { // Assuming 100 is max capacity
        return 9 // Higher compression if the network is under heavy load
    } else if currentLoad > 50 {
        return 6 // Moderate compression
    }
    return 3 // Lower compression if load is minimal
}


// EncodeToGob converts data into GOB format for compression.
func EncodeToGob(data interface{}) ([]byte, error) {
    var buf bytes.Buffer
    enc := gob.NewEncoder(&buf)
    if err := enc.Encode(data); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

// DecodeFromGob decodes GOB formatted data after decompression.
func DecodeFromGob(data []byte, target interface{}) error {
    buf := bytes.NewReader(data)
    dec := gob.NewDecoder(buf)
    return dec.Decode(target)
}

var once sync.Once
var instance *Compressor

// Compressor provides a singleton instance for compression tasks.
type Compressor struct{}

// GetInstance returns a singleton instance of the compressor.
func GetInstance() *Compressor {
    once.Do(func() {
        instance = &Compressor{}
    })
    return instance
}

// Example logging setup
func init() {
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

// LogError logs error messages to the console and potentially a log file.
func LogError(err error) {
    if err != nil {
        log.Printf("Error: %v", err)
    }
}

// Additional utility functions and comprehensive error handling can be added here.

