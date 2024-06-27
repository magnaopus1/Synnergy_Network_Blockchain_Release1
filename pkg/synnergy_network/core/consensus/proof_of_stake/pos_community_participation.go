package consensus

import (
    "math/big"
    "time"
    "fmt"
)

// CommunityParticipant defines the attributes of a single staker in the network
type CommunityParticipant struct {
    ID             string
    StakedAmount   *big.Int
    StakingStart   time.Time
    IsValidator    bool
    VotedOn        map[string]bool
    Slashed        bool
}

// CommunityPool manages all participants and their activities within the network
type CommunityPool struct {
    Participants map[string]*CommunityParticipant
    TotalStaked  *big.Int
    StakingRules *StakingRules
}

type StakingRules struct {
    MinStake         *big.Int
    MaxValidatorSize int
}

// NewCommunityPool initializes a new community pool with staking rules
func NewCommunityPool(minStake *big.Int, maxValidators int) *CommunityPool {
    return &CommunityPool{
        Participants: make(map[string]*CommunityParticipant),
        TotalStaked:  big.NewInt(0),
        StakingRules: &StakingRules{
            MinStake:         minStake,
            MaxValidatorSize: maxValidators,
        },
    }
}

// AddParticipant adds a new participant to the pool
func (cp *CommunityPool) AddParticipant(participant *CommunityParticipant) error {
    if participant.StakedAmount.Cmp(cp.StakingRules.MinStake) < 0 {
        return fmt.Errorf("minimum stake requirement not met")
    }
    cp.Participants[participant.ID] = participant
    cp.TotalStaked.Add(cp.TotalStaked, participant.StakedAmount)
    return nil
}

// StakeTokens handles staking logic for a participant
func (cp *CommunityPool) StakeTokens(participantID string, amount *big.Int) error {
    participant, exists := cp.Participants[participantID]
    if !exists {
        return fmt.Errorf("participant not found")
    }
    if amount.Cmp(cp.StakingRules.MinStake) < 0 {
        return fmt.Errorf("amount is less than the minimum stake requirement")
    }
    participant.StakedAmount.Add(participant.StakedAmount, amount)
    cp.TotalStaked.Add(cp.TotalStaked, amount)
    participant.StakingStart = time.Now()
    return nil
}

// SlashParticipant applies a penalty to a participant's stake for misbehavior
func (cp *CommunityPool) SlashParticipant(participantID string, penalty *big.Int) error {
    participant, exists := cp.Participants[participantID]
    if !exists || participant.Slashed {
        return fmt.Errorf("participant not found or already slashed")
    }
    if participant.StakedAmount.Cmp(penalty) <= 0 {
        participant.StakedAmount.SetInt64(0)
    } else {
        participant.StakedAmount.Sub(participant.StakedAmount, penalty)
    }
    participant.Slashed = true
    return nil
}

// InitiateVote allows participants to vote on governance proposals
func (cp *CommunityPool) InitiateVote(participantID string, proposalID string) error {
    participant, exists := cp.Participants[participantID]
    if !exists {
        return fmt.Errorf("participant not found")
    }
    if _, voted := participant.VotedOn[proposalID]; voted {
        return fmt.Errorf("participant has already voted on this proposal")
    }
    participant.VotedOn[proposalID] = true
    return nil
}

// CalculateVotingPower calculates the voting power of a participant based on staked tokens
func (cp *CommunityPool) CalculateVotingPower(participantID string) (*big.Int, error) {
    participant, exists := cp.Participants[participantID]
    if !exists {
        return nil, fmt.Errorf("participant not found")
    }
    // Voting power could be adjusted here to incorporate factors such as stake duration
    return new(big.Int).Set(participant.StakedAmount), nil
}

// UpdateStakingRules dynamically adjusts the staking rules based on the total staked amount
func (cp *CommunityPool) UpdateStakingRules(newMinStake *big.Int, maxValidators int) {
    cp.StakingRules.MinStake = newMinStake
    cp.StakingRules.MaxValidatorSize = maxValidators
}
