package blockchain_compression

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
)

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

// CreateDifferential calculates the differences between two blocks.
func CreateDifferential(oldBlock, newBlock *Block) ([]Differential, error) {
	oldData, err := json.Marshal(oldBlock)
	if err != nil {
		return nil, err
	}
	newData, err := json.Marshal(newBlock)
	if err != nil {
		return nil, err
	}

	var oldMap, newMap map[string]interface{}
	if err := json.Unmarshal(oldData, &oldMap); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(newData, &newMap); err != nil {
		return nil, err
	}

	var differentials []Differential
	for key, oldValue := range oldMap {
		if newValue, exists := newMap[key]; exists {
			if newValue != oldValue {
				differentials = append(differentials, Differential{
					Field:    key,
					OldValue: oldValue,
					NewValue: newValue,
				})
			}
		} else {
			differentials = append(differentials, Differential{
				Field:    key,
				OldValue: oldValue,
				NewValue: nil,
			})
		}
	}

	for key, newValue := range newMap {
		if _, exists := oldMap[key]; !exists {
			differentials = append(differentials, Differential{
				Field:    key,
				OldValue: nil,
				NewValue: newValue,
			})
		}
	}

	return differentials, nil
}

// ApplyDifferential applies the differentials to the old block to create the new block.
func ApplyDifferential(oldBlock *Block, differentials []Differential) (*Block, error) {
	oldData, err := json.Marshal(oldBlock)
	if err != nil {
		return nil, err
	}

	var oldMap map[string]interface{}
	if err := json.Unmarshal(oldData, &oldMap); err != nil {
		return nil, err
	}

	for _, diff := range differentials {
		if diff.NewValue == nil {
			delete(oldMap, diff.Field)
		} else {
			oldMap[diff.Field] = diff.NewValue
		}
	}

	newData, err := json.Marshal(oldMap)
	if err != nil {
		return nil, err
	}

	var newBlock Block
	if err := json.Unmarshal(newData, &newBlock); err != nil {
		return nil, err
	}

	return &newBlock, nil
}

// DifferentialSync synchronizes blocks using differential compression.
func DifferentialSync(oldBlock, newBlock *Block) ([]byte, error) {
	differentials, err := CreateDifferential(oldBlock, newBlock)
	if err != nil {
		return nil, err
	}

	differentialData, err := json.Marshal(differentials)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(differentialData); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ApplySyncDelta applies a synchronization delta to the old block to recreate the new block.
func ApplySyncDelta(oldBlock *Block, delta []byte) (*Block, error) {
	buf := bytes.NewBuffer(delta)
	reader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}

	differentialData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var differentials []Differential
	if err := json.Unmarshal(differentialData, &differentials); err != nil {
		return nil, err
	}

	newBlock, err := ApplyDifferential(oldBlock, differentials)
	if err != nil {
		return nil, err
	}

	return newBlock, nil
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

// NewBlock creates a new block.
func NewBlock(index int, previousHash, data string, prunable bool) *Block {
	return &Block{
		Index:        index,
		PreviousHash: previousHash,
		Timestamp:    time.Now().Unix(),
		Data:         data,
		Hash:         CalculateHash(index, previousHash, data),
		Prunable:     prunable,
	}
}

// CalculateHash calculates the hash of a block.
func CalculateHash(index int, previousHash, data string) string {
	// Implement a suitable hash function
	// Example: return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%s%s", index, previousHash, data))))
	return ""
}

// AddBlock adds a block to the blockchain.
func (bc *Blockchain) AddBlock(block *Block) {
	bc.Blocks = append(bc.Blocks, block)
}

// PruneBlock prunes a block from the blockchain.
func (bc *Blockchain) PruneBlock(index int) error {
	if index < 0 || index >= len(bc.Blocks) {
		return errors.New("block index out of range")
	}
	if !bc.Blocks[index].Prunable {
		return errors.New("block is not prunable")
	}
	bc.Blocks = append(bc.Blocks[:index], bc.Blocks[index+1:]...)
	return nil
}

// SelectivePruning selectively prunes prunable blocks based on a condition.
func (bc *Blockchain) SelectivePruning(condition func(*Block) bool) {
	for i := len(bc.Blocks) - 1; i >= 0; i-- {
		block := bc.Blocks[i]
		if block.Prunable && condition(block) {
			bc.PruneBlock(i)
		}
	}
}

// Condition example: prune blocks older than 30 days
func PruneOlderThan30Days(block *Block) bool {
	return time.Now().Unix()-block.Timestamp > 30*24*60*60
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
