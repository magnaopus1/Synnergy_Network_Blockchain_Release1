package consensus

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

// CommunityParticipation manages community involvement and reward distribution.
type CommunityParticipation struct {
	Participants map[string]*MinerProfile
	Blockchain   *common.Blockchain
	lock         sync.Mutex
}

// MinerProfile stores details about each miner's capabilities and engagement.
type MinerProfile struct {
	ID            string
	HashPower     float64
	Stake         float64
	Participating bool
}

// NewCommunityParticipation initializes the community participation handler.
func NewCommunityParticipation(blockchain *common.Blockchain) *CommunityParticipation {
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
func (cp *CommunityParticipation) CalculateCommunityReward(block *common.Block) {
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
			reward := new(big.Float).Mul(new(big.Float).Quo(new(big.Float).SetFloat64(miner.HashPower), new(big.Float).SetFloat64(totalPower)), new(big.Float).SetInt(block.Reward))
			rewardInt, _ := reward.Int(nil) // Convert big.Float to big.Int
			cp.transferReward(miner.ID, rewardInt)
		}
	}
}

// transferReward simulates the transfer of mining rewards to the miner's wallet.
func (cp *CommunityParticipation) transferReward(minerID string, amount *big.Int) {
	// This function would interact with a wallet service or similar to credit the miner
	// Example: WalletService.Credit(minerID, amount)
}

// GenerateBlock simulates block generation, typically called by a mining algorithm.
func (cp *CommunityParticipation) GenerateBlock(transactions []*common.Transaction, prevHash string, reward *big.Int) *common.Block {
	return &common.Block{
		PrevBlockHash: prevHash,
		Transactions:  transactions,
		Reward:        reward,
	}
}
