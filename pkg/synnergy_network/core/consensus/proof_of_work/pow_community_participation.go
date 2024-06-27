package consensus

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
)

// CommunityParticipation manages community involvement and reward distribution.
type CommunityParticipation struct {
	Participants map[string]*MinerProfile
	Blockchain   *Blockchain
	lock         sync.Mutex
}

// MinerProfile stores details about each miner's capabilities and engagement.
type MinerProfile struct {
	ID            string
	HashPower     float64
	Stake         float64
	Participating bool
}

// Blockchain represents a simplified version of the blockchain maintained by the network.
type Blockchain struct {
	Blocks []*Block
}

// NewCommunityParticipation initializes the community participation handler.
func NewCommunityParticipation(blockchain *Blockchain) *CommunityParticipation {
	return &CommunityParticipation{
		Participants: make(map[string]*MinerProfile),
		Blockchain:   blockchain,
	}
}

// RegisterMiner adds a new miner to the community participation pool.
func (cp *CommunityParticipation) RegisterMiner(hashPower, stake float64) (string, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()

	idBytes := make([]byte, 16)
	_, err := rand.Read(idBytes)
	if err != nil {
		return "", err
	}

	minerID := hex.EncodeToString(idBytes)
	cp.Participants[minerID] = &MinerProfile{
		ID:            minerID,
		HashPower:     hashPower,
		Stake:         stake,
		Participating: true,
	}

	return minerID, nil
}

// UpdateMinerActivity changes the participation status of a miner.
func (cp *CommunityParticipation) UpdateMinerActivity(minerID string, participating bool) error {
	cp.lock.Lock()
	defer cp.lock.Unlock()

	miner, exists := cp.Participants[minerID]
	if !exists {
		return errors.New("miner not found")
	}

	miner.Participating = participating
	return nil
}

// CalculateCommunityReward distributes mining rewards among active participants based on their hash power and stake.
func (cp *CommunityParticipation) CalculateCommunityReward(block *Block) {
	cp.lock.Lock()
	defer cp.lock.Unlock()

	totalPower := 0.0
	for _, miner := range cp.Participants {
		if miner.Participating {
			totalPower += miner.HashPower
		}
	}

	for _, miner := range cp.Participants {
		if miner.Participating {
			reward := (miner.HashPower / totalPower) * block.Reward
			cp.transferReward(miner.ID, reward)
		}
	}
}

// transferReward simulates the transfer of mining rewards to the miner's wallet.
func (cp *CommunityParticipation) transferReward(minerID string, amount float64) {
	// This function would interact with a wallet service or similar to credit the miner
	// Example: WalletService.Credit(minerID, amount)
}

// GenerateBlock simulates block generation, typically called by a mining algorithm.
func (cp *CommunityParticipation) GenerateBlock(transactions []*Transaction, prevHash string, reward float64) *Block {
	return &Block{
		PrevHash:     prevHash,
		Transactions: transactions,
		Reward:       reward,
	}
}

// Block represents a basic block in the blockchain.
type Block struct {
	PrevHash     string
	Transactions []*Transaction
	Reward       float64
}

// Transaction represents a simplified transaction model.
type Transaction struct {
	Sender    string
	Receiver  string
	Amount    float64
	Fee       float64
}
