package resource_pools

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "sync"
    "time"
)

// IncentiveMechanisms manages the reward and incentive structures within the network
type IncentiveMechanisms struct {
    RewardPool          float64
    NodeIncentives      map[string]float64
    StakeholderRewards  map[string]float64
    mu                  sync.Mutex
    rewardDistribution  map[string]float64 // Node ID -> Reward Percentage
}

// NewIncentiveMechanisms initializes the incentive mechanisms with a reward pool
func NewIncentiveMechanisms(initialRewardPool float64) *IncentiveMechanisms {
    return &IncentiveMechanisms{
        RewardPool:         initialRewardPool,
        NodeIncentives:     make(map[string]float64),
        StakeholderRewards: make(map[string]float64),
        rewardDistribution: make(map[string]float64),
    }
}

// AllocateRewards calculates and allocates rewards to nodes based on their contributions
func (im *IncentiveMechanisms) AllocateRewards() error {
    im.mu.Lock()
    defer im.mu.Unlock()

    if im.RewardPool <= 0 {
        return errors.New("insufficient reward pool")
    }

    totalContribution := 0.0
    for _, contribution := range im.rewardDistribution {
        totalContribution += contribution
    }

    if totalContribution == 0 {
        return errors.New("no contributions to reward")
    }

    for nodeID, contribution := range im.rewardDistribution {
        percentage := contribution / totalContribution
        reward := percentage * im.RewardPool
        im.NodeIncentives[nodeID] += reward
    }

    im.RewardPool = 0 // Reset the reward pool after distribution
    return nil
}

// RecordContribution records the contributions of nodes for reward calculation
func (im *IncentiveMechanisms) RecordContribution(nodeID string, contribution float64) {
    im.mu.Lock()
    defer im.mu.Unlock()

    if contribution <= 0 {
        return
    }

    if _, exists := im.rewardDistribution[nodeID]; !exists {
        im.rewardDistribution[nodeID] = 0
    }
    im.rewardDistribution[nodeID] += contribution
}

// ResetContributions resets the recorded contributions after rewards are allocated
func (im *IncentiveMechanisms) ResetContributions() {
    im.mu.Lock()
    defer im.mu.Unlock()

    for nodeID := range im.rewardDistribution {
        im.rewardDistribution[nodeID] = 0
    }
}

// EncryptRewardData encrypts the reward data for secure storage or transmission
func EncryptRewardData(data []byte, passphrase string) (string, error) {
    block, err := aes.NewCipher([]byte(passphrase))
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

    return hex.EncodeToString(ciphertext), nil
}

// DecryptRewardData decrypts the reward data
func DecryptRewardData(encryptedData string, passphrase string) ([]byte, error) {
    ciphertext, err := hex.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher([]byte(passphrase))
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return ciphertext, nil
}

// HashContributionData hashes the contribution data for integrity verification
func HashContributionData(data string) string {
    hash := sha256.New()
    hash.Write([]byte(data))
    return hex.EncodeToString(hash.Sum(nil))
}

// PayoutIncentives pays out the accumulated incentives to nodes
func (im *IncentiveMechanisms) PayoutIncentives() map[string]float64 {
    im.mu.Lock()
    defer im.mu.Unlock()

    payouts := make(map[string]float64)
    for nodeID, incentive := range im.NodeIncentives {
        payouts[nodeID] = incentive
        im.NodeIncentives[nodeID] = 0 // Reset the incentive after payout
    }

    return payouts
}

// StakeholderReward allocates rewards to stakeholders based on their stake and contribution
func (im *IncentiveMechanisms) StakeholderReward(stakeholders map[string]float64, totalStake float64) error {
    im.mu.Lock()
    defer im.mu.Unlock()

    if im.RewardPool <= 0 {
        return errors.New("insufficient reward pool")
    }

    if totalStake == 0 {
        return errors.New("total stake cannot be zero")
    }

    for stakeholderID, stake := range stakeholders {
        percentage := stake / totalStake
        reward := percentage * im.RewardPool
        im.StakeholderRewards[stakeholderID] += reward
    }

    im.RewardPool = 0 // Reset the reward pool after distribution
    return nil
}
