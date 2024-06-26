package block

import (
    "bytes"
    "compress/gzip"
    "compress/zlib"
    "io/ioutil"
    "sync"

    "github.com/klauspost/compress/zstd"
    "github.com/pkg/errors"
)

// CompressionType defines the type of compression used.
type CompressionType int

const (
    GZIP CompressionType = iota
    ZLIB
    ZSTD
)

// BlockCompression handles the compression and decompression of blocks.
type BlockCompression struct {
    Type CompressionType
    mu   sync.Mutex
}

// NewBlockCompression creates a new BlockCompression instance.
func NewBlockCompression(compressionType CompressionType) *BlockCompression {
    return &BlockCompression{
        Type: compressionType,
        mu:   sync.Mutex{},
    }
}

// Compress compresses the given block data using the specified compression algorithm.
func (bc *BlockCompression) Compress(data []byte) ([]byte, error) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    var compressedData bytes.Buffer
    var err error

    switch bc.Type {
    case GZIP:
        writer := gzip.NewWriter(&compressedData)
        _, err = writer.Write(data)
        if err != nil {
            return nil, errors.Wrap(err, "gzip compression failed")
        }
        writer.Close()
    case ZLIB:
        writer := zlib.NewWriter(&compressedData)
        _, err = writer.Write(data)
        if err != nil {
            return nil, errors.Wrap(err, "zlib compression failed")
        }
        writer.Close()
    case ZSTD:
        encoder, err := zstd.NewWriter(&compressedData)
        if err != nil {
            return nil, errors.Wrap(err, "zstd compression initialization failed")
        }
        _, err = encoder.Write(data)
        if err != nil {
            return nil, errors.Wrap(err, "zstd compression failed")
        }
        encoder.Close()
    default:
        return nil, errors.New("unsupported compression type")
    }

    return compressedData.Bytes(), nil
}

// Decompress decompresses the given block data using the specified compression algorithm.
func (bc *BlockCompression) Decompress(data []byte) ([]byte, error) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    var decompressedData bytes.Buffer
    var err error

    switch bc.Type {
    case GZIP:
        reader, err := gzip.NewReader(bytes.NewReader(data))
        if err != nil {
            return nil, errors.Wrap(err, "gzip decompression failed")
        }
        decompressedData.ReadFrom(reader)
        reader.Close()
    case ZLIB:
        reader, err := zlib.NewReader(bytes.NewReader(data))
        if err != nil {
            return nil, errors.Wrap(err, "zlib decompression failed")
        }
        decompressedData.ReadFrom(reader)
        reader.Close()
    case ZSTD:
        decoder, err := zstd.NewReader(bytes.NewReader(data))
        if err != nil {
            return nil, errors.Wrap(err, "zstd decompression initialization failed")
        }
        decompressedData.ReadFrom(decoder)
        decoder.Close()
    default:
        return nil, errors.New("unsupported decompression type")
    }

    return decompressedData.Bytes(), nil
}

// CompressBlock compresses the block using the specified compression type.
func CompressBlock(block Block, compressionType CompressionType) (Block, error) {
    blockData, err := blockToBytes(block)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to convert block to bytes")
    }

    compressor := NewBlockCompression(compressionType)
    compressedData, err := compressor.Compress(blockData)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to compress block data")
    }

    compressedBlock, err := bytesToBlock(compressedData)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to convert bytes to block")
    }

    return compressedBlock, nil
}

// DecompressBlock decompresses the block using the specified decompression type.
func DecompressBlock(compressedBlock Block, compressionType CompressionType) (Block, error) {
    blockData, err := blockToBytes(compressedBlock)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to convert block to bytes")
    }

    decompressor := NewBlockCompression(compressionType)
    decompressedData, err := decompressor.Decompress(blockData)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to decompress block data")
    }

    block, err := bytesToBlock(decompressedData)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to convert bytes to block")
    }

    return block, nil
}

// Helper functions to convert a block to bytes and vice versa.
func blockToBytes(block Block) ([]byte, error) {
    var buf bytes.Buffer
    encoder := gob.NewEncoder(&buf)
    err := encoder.Encode(block)
    if err != nil {
        return nil, errors.Wrap(err, "failed to encode block")
    }
    return buf.Bytes(), nil
}

func bytesToBlock(data []byte) (Block, error) {
    var block Block
    buf := bytes.NewBuffer(data)
    decoder := gob.NewDecoder(buf)
    err := decoder.Decode(&block)
    if err != nil {
        return Block{}, errors.Wrap(err, "failed to decode block")
    }
    return block, nil
}
