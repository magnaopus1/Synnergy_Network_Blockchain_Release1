// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including node participation in the consensus mechanism.
package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// ConsensusParticipation manages the participation of a node in the consensus mechanism.
type ConsensusParticipation struct {
	NodeID              string
	ConsensusAlgorithm  string
	PowDifficulty       int
	ConsensusData       map[string]interface{}
	mutex               sync.Mutex
	Mining              bool
	NewBlockCallback    func(block Block)
	ConsensusVoteCallback func(vote ConsensusVote)
}

// Block represents a basic structure of a block in the blockchain.
type Block struct {
	Index        int
	Timestamp    int64
	PreviousHash string
	Hash         string
	Data         string
	Nonce        string
}

// ConsensusVote represents a vote in the consensus process.
type ConsensusVote struct {
	NodeID      string
	BlockHash   string
	Signature   string
}

// NewConsensusParticipation creates a new ConsensusParticipation instance.
func NewConsensusParticipation(nodeID, algorithm string, difficulty int, newBlockCallback func(Block), consensusVoteCallback func(ConsensusVote)) *ConsensusParticipation {
	return &ConsensusParticipation{
		NodeID:              nodeID,
		ConsensusAlgorithm:  algorithm,
		PowDifficulty:       difficulty,
		ConsensusData:       make(map[string]interface{}),
		NewBlockCallback:    newBlockCallback,
		ConsensusVoteCallback: consensusVoteCallback,
	}
}

// StartMining starts the mining process for proof-of-work consensus.
func (cp *ConsensusParticipation) StartMining(data string, previousHash string) error {
	if cp.ConsensusAlgorithm != "pow" {
		return errors.New("mining is only applicable for proof-of-work consensus")
	}

	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if cp.Mining {
		return errors.New("mining is already in progress")
	}

	cp.Mining = true
	go cp.mineBlock(data, previousHash)
	return nil
}

// mineBlock performs the actual mining process.
func (cp *ConsensusParticipation) mineBlock(data string, previousHash string) {
	var nonce int
	var hash string
	target := fmt.Sprintf("%0*x", cp.PowDifficulty, 0)

	for cp.Mining {
		nonce++
		hash = cp.calculateHash(data, previousHash, nonce)
		if hash[:cp.PowDifficulty] == target {
			cp.Mining = false
			block := Block{
				Index:        len(cp.ConsensusData),
				Timestamp:    time.Now().Unix(),
				PreviousHash: previousHash,
				Hash:         hash,
				Data:         data,
				Nonce:        fmt.Sprintf("%x", nonce),
			}
			cp.ConsensusData[hash] = block
			cp.NewBlockCallback(block)
			break
		}
	}
}

// StopMining stops the mining process.
func (cp *ConsensusParticipation) StopMining() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.Mining = false
}

// calculateHash calculates the hash for a block.
func (cp *ConsensusParticipation) calculateHash(data, previousHash string, nonce int) string {
	record := fmt.Sprintf("%s:%s:%d", data, previousHash, nonce)
	hash := sha256.New()
	hash.Write([]byte(record))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// ValidateBlock validates the block using the appropriate consensus algorithm.
func (cp *ConsensusParticipation) ValidateBlock(block Block) bool {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	switch cp.ConsensusAlgorithm {
	case "pow":
		target := fmt.Sprintf("%0*x", cp.PowDifficulty, 0)
		return block.Hash[:cp.PowDifficulty] == target
	case "pos":
		// Implement proof-of-stake validation logic here
		return true
	case "poh":
		// Implement proof-of-history validation logic here
		return true
	case "dpos":
		// Implement delegated proof-of-stake validation logic here
		return true
	default:
		return false
	}
}

// CastVote casts a vote for a block in the consensus process.
func (cp *ConsensusParticipation) CastVote(blockHash string) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if _, exists := cp.ConsensusData[blockHash]; !exists {
		return errors.New("block does not exist")
	}

	vote := ConsensusVote{
		NodeID:    cp.NodeID,
		BlockHash: blockHash,
		Signature: cp.signData(blockHash),
	}

	cp.ConsensusVoteCallback(vote)
	return nil
}

// signData signs the data for the consensus vote.
func (cp *ConsensusParticipation) signData(data string) string {
	// Placeholder for a real signing implementation.
	// In a real-world scenario, use a cryptographic function to sign the data.
	return hex.EncodeToString(argon2.IDKey([]byte(data), []byte(cp.NodeID), 1, 64*1024, 4, 32))
}

// handleNewBlock handles the new block creation process.
func (cp *ConsensusParticipation) handleNewBlock(block Block) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	cp.ConsensusData[block.Hash] = block
}

// handleConsensusVote handles the consensus voting process.
func (cp *ConsensusParticipation) handleConsensusVote(vote ConsensusVote) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	// Placeholder for handling votes. In a real-world scenario, validate the vote and take appropriate actions.
}

// SetConsensusData sets the consensus data.
func (cp *ConsensusParticipation) SetConsensusData(key string, value interface{}) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	cp.ConsensusData[key] = value
}

// GetConsensusData gets the consensus data.
func (cp *ConsensusParticipation) GetConsensusData(key string) (interface{}, bool) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	value, exists := cp.ConsensusData[key]
	return value, exists
}
