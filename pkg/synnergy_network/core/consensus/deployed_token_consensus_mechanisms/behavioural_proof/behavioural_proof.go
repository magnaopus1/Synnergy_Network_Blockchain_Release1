package behavioural_proof

import (
	"errors"
	"sync"
	"time"
)

// Validator stores information about each participant in the network.
type Validator struct {
	ID                   string
	UptimeScore          float64
	AccuracyScore        float64
	CommunityContributionScore float64
	ReputationScore      float64
	LastParticipation    time.Time
}

// BehaviouralProof represents the main class for the Behavioural Proof consensus mechanism.
type BehaviouralProof struct {
	validators      map[string]*Validator
	weightingFactors WeightingFactors
	lock             sync.RWMutex
}

// WeightingFactors define the relative importance of each aspect of a validator's performance.
type WeightingFactors struct {
	UptimeWeight        float64
	AccuracyWeight      float64
	CommunityWeight     float64
}

// NewBehaviouralProof initializes a new instance of BehaviouralProof consensus mechanism.
func NewBehaviouralProof() *BehaviouralProof {
	return &BehaviouralProof{
		validators: make(map[string]*Validator),
		weightingFactors: WeightingFactors{
			UptimeWeight:    0.4,
			AccuracyWeight:  0.4,
			CommunityWeight: 0.2,
		},
	}
}

// RegisterValidator adds a new validator to the network.
func (bp *BehaviouralProof) RegisterValidator(validatorID string) error {
	bp.lock.Lock()
	defer bp.lock.Unlock()

	if _, exists := bp.validators[validatorID]; exists {
		return errors.New("validator already registered")
	}

	bp.validators[validatorID] = &Validator{
		ID: validatorID,
	}
	return nil
}

// UpdateValidatorScores updates the scores of a validator based on new data.
func (bp *BehaviouralProof) UpdateValidatorScores(validatorID string, uptime, accuracy, community float64) error {
	bp.lock.Lock()
	defer bp.lock.Unlock()

	validator, exists := bp.validators[validatorID]
	if !exists {
		return errors.New("validator not found")
	}

	validator.UptimeScore = uptime
	validator.AccuracyScore = accuracy
	validator.CommunityContributionScore = community
	validator.ReputationScore = bp.calculateReputation(validator)

	return nil
}

// calculateReputation computes the reputation score of a validator based on the current weighting factors.
func (bp *BehaviouralProof) calculateReputation(v *Validator) float64 {
	return v.UptimeScore*bp.weightingFactors.UptimeWeight +
		v.AccuracyScore*bp.weightingFactors.AccuracyWeight +
		v.CommunityContributionScore*bp.weightingFactors.CommunityWeight
}

// SelectValidators selects validators for the consensus process based on their reputation scores.
func (bp *BehaviouralProof) SelectValidators(count int) ([]*Validator, error) {
	bp.lock.RLock()
	defer bp.lock.RUnlock()

	var sortedValidators ValidatorList
	for _, v := range bp.validators {
		sortedValidators = append(sortedValidators, v)
	}
	sortedValidators.SortByReputation()

	if count > len(sortedValidators) {
		return nil, errors.New("not enough validators to select from")
	}
	return sortedValidators[:count], nil
}

// ApplyPenalties applies penalties to a validator's scores based on detected behaviors.
func (bp *BehaviouralProof) ApplyPenalties(validatorID string, penaltyType string) error {
	bp.lock.Lock()
	defer bp.lock.Unlock()

	validator, exists := bp.validators[validatorID]
	if !exists {
		return errors.New("validator not found")
	}

	switch penaltyType {
	case "downtime":
		validator.ReputationScore *= 0.95 // Decrease reputation by 5% for downtime
	case "inaccuracy":
		validator.ReputationScore *= 0.90 // Decrease reputation by 10% for inaccurate transactions
	case "negativeImpact":
		validator.ReputationScore *= 0.85 // Decrease reputation by 15% for negative community impact
	default:
		return errors.New("unknown penalty type")
	}

	return nil
}

// ValidatorList is a custom type for sorting validators by their reputation.
type ValidatorList []*Validator

func (vl ValidatorList) Len() int {
	return len(vl)
}

func (vl ValidatorList) Swap(i, j int) {
	vl[i], vl[j] = vl[j], vl[i]
}

func (vl ValidatorList) Less(i, j int) bool {
	return vl[i].ReputationScore > vl[j].ReputationScore
}

func (vl *ValidatorList) SortByReputation() {
	sort.Sort(vl)
}

