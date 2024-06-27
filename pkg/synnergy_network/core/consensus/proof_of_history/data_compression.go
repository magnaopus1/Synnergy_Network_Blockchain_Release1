package consensus

import (
    "bytes"
    "compress/gzip"
    "io"
)

// DataCompressor encapsulates methods for compressing and decompressing blockchain data.
type DataCompressor struct{}

// NewDataCompressor creates a new instance of DataCompressor.
func NewDataCompressor() *DataCompressor {
    return &DataCompressor{}
}

// CompressData compresses transaction data using gzip to reduce its size for efficient block propagation.
func (dc *DataCompressor) CompressData(data []byte) ([]byte, error) {
    var buf bytes.Buffer
    gzipWriter := gzip.NewWriter(&buf)
    _, err := gzipWriter.Write(data)
    if err != nil {
        return nil, err
    }

    if err := gzipWriter.Close(); err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

// DecompressData decompresses transaction data using gzip, restoring it to its original form for processing.
func (dc *DataCompressor) DecompressData(compressedData []byte) ([]byte, error) {
    var buf bytes.Buffer
    buf.Write(compressedData)

    gzipReader, err := gzip.NewReader(&buf)
    if err != nil {
        return nil, err
    }
    defer gzipReader.Close()

    decompressedData, err := io.ReadAll(gzipReader)
    if err != nil {
        return nil, err
    }

    return decompressedData, nil
}

// IntegrateCompressionIntoBlockchain integrates data compression and decompression into the blockchain handling processes.
func IntegrateCompressionIntoBlockchain() {
    // Placeholder for integration logic, such as modifying block data handling to incorporate compression.
    // Example: Adjust block creation, validation, and synchronization processes to use compressed data.
}
