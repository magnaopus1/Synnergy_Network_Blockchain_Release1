package block

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network/crypto"
)

// BlockHeader represents the metadata of a block in the blockchain.
type BlockHeader struct {
	PreviousHash    string    `json:"previous_hash"`
	Timestamp       time.Time `json:"timestamp"`
	Nonce           int       `json:"nonce"`
	MerkleRoot      string    `json:"merkle_root"`
	Difficulty      int       `json:"difficulty"`
	Hash            string    `json:"hash"`
	ValidatorPubKey string    `json:"validator_pub_key"`
}

// NewBlockHeader creates a new BlockHeader with the provided details.
func NewBlockHeader(previousHash string, difficulty int, validatorPubKey string) *BlockHeader {
	return &BlockHeader{
		PreviousHash:    previousHash,
		Timestamp:       time.Now(),
		Nonce:           0,
		MerkleRoot:      "",
		Difficulty:      difficulty,
		ValidatorPubKey: validatorPubKey,
	}
}

// CalculateHash computes the hash of the block header.
func (bh *BlockHeader) CalculateHash() string {
	headerBytes, _ := json.Marshal(bh)
	hash := sha256.Sum256(headerBytes)
	return hex.EncodeToString(hash[:])
}

// SetMerkleRoot sets the Merkle root for the block header.
func (bh *BlockHeader) SetMerkleRoot(merkleRoot string) {
	bh.MerkleRoot = merkleRoot
}

// IncrementNonce increments the nonce value for the block header.
func (bh *BlockHeader) IncrementNonce() {
	bh.Nonce++
}

// ValidateHash checks if the block header hash satisfies the difficulty requirements.
func (bh *BlockHeader) ValidateHash() bool {
	hashBytes, _ := hex.DecodeString(bh.Hash)
	for i := 0; i < bh.Difficulty; i++ {
		if hashBytes[i] != 0 {
			return false
		}
	}
	return true
}

// MineBlock performs the mining operation to find a valid hash for the block header.
func (bh *BlockHeader) MineBlock() error {
	for {
		bh.Hash = bh.CalculateHash()
		if bh.ValidateHash() {
			return nil
		}
		bh.IncrementNonce()
	}
}

// SignBlockHeader signs the block header with the validator's private key.
func (bh *BlockHeader) SignBlockHeader(privateKey string) (string, error) {
	headerBytes, err := json.Marshal(bh)
	if err != nil {
		return "", err
	}
	signature, err := crypto.SignData(headerBytes, privateKey)
	if err != nil {
		return "", err
	}
	return signature, nil
}

// VerifyBlockHeader verifies the signature of the block header.
func (bh *BlockHeader) VerifyBlockHeader(signature, publicKey string) error {
	headerBytes, err := json.Marshal(bh)
	if err != nil {
		return err
	}
	if !crypto.VerifySignature(headerBytes, signature, publicKey) {
		return errors.New("invalid block header signature")
	}
	return nil
}

// Serialize converts the block header to a byte array.
func (bh *BlockHeader) Serialize() ([]byte, error) {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)
	err := encoder.Encode(bh)
	if err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

// DeserializeBlockHeader converts a byte array back to a BlockHeader.
func DeserializeBlockHeader(data []byte) (*BlockHeader, error) {
	var bh BlockHeader
	reader := bytes.NewReader(data)
	decoder := gob.NewDecoder(reader)
	err := decoder.Decode(&bh)
	if err != nil {
		return nil, err
	}
	return &bh, nil
}
