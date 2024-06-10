package dynamicblocksizes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"math"
	"sync"
)

// BlockSizeManager manages the size of blocks dynamically based on network throughput and transaction volume.
type BlockSizeManager struct {
	CurrentSize   int
	MinSize       int
	MaxSize       int
	AdjustmentFactor float64
	lock          sync.Mutex
}

// NewBlockSizeManager creates a new BlockSizeManager with specified minimum and maximum sizes.
func NewBlockSizeManager(minSize, maxSize int, adjustmentFactor float64) *BlockSizeManager {
	return &BlockSizeManager{
		CurrentSize: minSize,
		MinSize:     minSize,
		MaxSize:     maxSize,
		AdjustmentFactor: adjustmentFactor,
	}
}

// AdjustBlockSize dynamically adjusts the block size based on transaction volume and network conditions.
func (bsm *BlockSizeManager) AdjustBlockSize(transactionCount int) {
	bsm.lock.Lock()
	defer bsm.lock.Unlock()

	// Example logic to adjust block size
	newSize := int(float64(bsm.CurrentSize) * (1 + (float64(transactionCount)/1000 * bsm.AdjustmentFactor)))

	if newSize > bsm.MaxSize {
		newSize = bsm.MaxSize
	} else if newSize < bsm.MinSize {
		newSize = bsm.MinSize
	}

	bsm.CurrentSize = newSize
	log.Printf("Block size adjusted to %d based on transaction volume", newSize)
}

// EncryptCurrentSize encrypts the current block size using AES-256.
func (bsm *BlockSizeManager) EncryptCurrentSize(key []byte) ([]byte, error) {
	bsm.lock.Lock()
	defer bsm.lock.Unlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	data := make([]byte, blockSize)
	binary.LittleEndian.PutUint32(data, uint32(bsm.CurrentSize))

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// DecryptSize decrypts the encrypted size data back to integer.
func DecryptSize(data, key []byte) (int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}

	if len(data) < aes.BlockSize {
		return 0, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	size := binary.LittleEndian.Uint32(data)
	return int(size), nil
}
