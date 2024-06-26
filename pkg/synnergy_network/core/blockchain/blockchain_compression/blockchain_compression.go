package blockchain_compression

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
)

// Data structure representing a blockchain block.
type Block struct {
	Index        int
	PreviousHash string
	Timestamp    int64
	Data         string
	Hash         string
}

// CompressBlock compresses the block data using gzip.
func CompressBlock(block *Block) ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gzipWriter).Encode(block); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressBlock decompresses the gzip data back into a block.
func DecompressBlock(compressedData []byte) (*Block, error) {
	buf := bytes.NewBuffer(compressedData)
	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	var block Block
	if err := json.NewDecoder(gzipReader).Decode(&block); err != nil {
		return nil, err
	}
	if err := gzipReader.Close(); err != nil {
		return nil, err
	}
	return &block, nil
}

// PruneBlock removes unnecessary data from the block to reduce its size.
func PruneBlock(block *Block, fieldsToKeep []string) (*Block, error) {
	prunedBlock := &Block{}
	blockBytes, err := json.Marshal(block)
	if err != nil {
		return nil, err
	}

	blockMap := make(map[string]interface{})
	if err := json.Unmarshal(blockBytes, &blockMap); err != nil {
		return nil, err
	}

	prunedBlockMap := make(map[string]interface{})
	for _, field := range fieldsToKeep {
		if value, ok := blockMap[field]; ok {
			prunedBlockMap[field] = value
		}
	}

	prunedBlockBytes, err := json.Marshal(prunedBlockMap)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(prunedBlockBytes, prunedBlock); err != nil {
		return nil, err
	}

	return prunedBlock, nil
}

// DifferentialSync applies differential synchronization to the blockchain data.
func DifferentialSync(oldBlock, newBlock *Block) ([]byte, error) {
	oldData, err := json.Marshal(oldBlock)
	if err != nil {
		return nil, err
	}
	newData, err := json.Marshal(newBlock)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	delta := bytes.Buffer{}

	for i := range oldData {
		if i < len(newData) && oldData[i] != newData[i] {
			delta.WriteByte(newData[i])
		}
	}

	if _, err := writer.Write(delta.Bytes()); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ApplySyncDelta applies a synchronization delta to the old block data to recreate the new block.
func ApplySyncDelta(oldBlock *Block, delta []byte) (*Block, error) {
	oldData, err := json.Marshal(oldBlock)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(delta)
	reader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}

	deltaData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	newData := append(oldData[:len(oldData)-len(deltaData)], deltaData...)
	var newBlock Block
	if err := json.Unmarshal(newData, &newBlock); err != nil {
		return nil, err
	}

	return &newBlock, nil
}

// AdaptiveCompressionThreshold dynamically adjusts the compression threshold based on network conditions.
func AdaptiveCompressionThreshold(blocks []*Block, networkLoad int) ([]*Block, error) {
	if networkLoad < 0 || networkLoad > 100 {
		return nil, errors.New("invalid network load value")
	}

	compressedBlocks := make([]*Block, 0, len(blocks))
	for _, block := range blocks {
		if networkLoad < 50 {
			compressedBlock, err := CompressBlock(block)
			if err != nil {
				return nil, err
			}
			decompressedBlock, err := DecompressBlock(compressedBlock)
			if err != nil {
				return nil, err
			}
			compressedBlocks = append(compressedBlocks, decompressedBlock)
		} else {
			compressedBlocks = append(compressedBlocks, block)
		}
	}

	return compressedBlocks, nil
}
