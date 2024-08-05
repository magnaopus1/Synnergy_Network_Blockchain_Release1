package management

import (
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// GovernancePoolParameters manages the parameters of liquidity pools governed by a DAO
type GovernancePoolParameters struct {
	Pools         map[string]*GovernedPool
	Governance    *Governance
	Lock          sync.Mutex
}

// GovernedPool represents a liquidity pool with parameters managed by a DAO
type GovernedPool struct {
	ID            common.Hash
	TokenBalances map[string]*big.Float
	Parameters    *PoolParameters
}

// PoolParameters represents the configurable parameters of a liquidity pool
type PoolParameters struct {
	SwapFee       *big.Float
	WithdrawalFee *big.Float
	DepositFee    *big.Float
}

// Governance represents the DAO that governs the liquidity pools
type Governance struct {
	Proposals     map[string]*Proposal
	Votes         map[string]map[common.Address]bool
	Lock          sync.Mutex
}

// Proposal represents a proposal to change the parameters of a liquidity pool
type Proposal struct {
	ID            string
	PoolID        common.Hash
	NewParameters *PoolParameters
	Approvals     int
	Rejections    int
}

// NewGovernancePoolParameters creates a new GovernancePoolParameters instance
func NewGovernancePoolParameters() *GovernancePoolParameters {
	return &GovernancePoolParameters{
		Pools:      make(map[string]*GovernedPool),
		Governance: &Governance{Proposals: make(map[string]*Proposal), Votes: make(map[string]map[common.Address]bool)},
	}
}

// AddPool adds a new governed liquidity pool
func (gpp *GovernancePoolParameters) AddPool(poolID common.Hash, initialBalances map[string]*big.Float, initialParameters *PoolParameters) {
	gpp.Lock.Lock()
	defer gpp.Lock.Unlock()

	pool := &GovernedPool{
		ID:            poolID,
		TokenBalances: initialBalances,
		Parameters:    initialParameters,
	}
	gpp.Pools[poolID.Hex()] = pool
}

// ProposeParameterChange creates a proposal to change the parameters of a liquidity pool
func (g *Governance) ProposeParameterChange(poolID common.Hash, newParameters *PoolParameters) string {
	g.Lock.Lock()
	defer g.Lock.Unlock()

	proposalID := common.BytesToHash([]byte(poolID.Hex() + newParameters.SwapFee.String() + newParameters.WithdrawalFee.String() + newParameters.DepositFee.String())).Hex()
	proposal := &Proposal{
		ID:            proposalID,
		PoolID:        poolID,
		NewParameters: newParameters,
	}
	g.Proposals[proposalID] = proposal
	g.Votes[proposalID] = make(map[common.Address]bool)

	return proposalID
}

// VoteProposal allows a DAO member to vote on a proposal
func (g *Governance) VoteProposal(proposalID string, voter common.Address, approve bool) error {
	g.Lock.Lock()
	defer g.Lock.Unlock()

	proposal, exists := g.Proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if _, voted := g.Votes[proposalID][voter]; voted {
		return errors.New("voter has already voted")
	}

	g.Votes[proposalID][voter] = approve
	if approve {
		proposal.Approvals++
	} else {
		proposal.Rejections++
	}

	return nil
}

// ExecuteProposal executes a proposal if it has enough approvals
func (gpp *GovernancePoolParameters) ExecuteProposal(proposalID string) error {
	gpp.Governance.Lock.Lock()
	defer gpp.Governance.Lock.Unlock()

	proposal, exists := gpp.Governance.Proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Approvals <= proposal.Rejections {
		return errors.New("proposal not approved")
	}

	pool, exists := gpp.Pools[proposal.PoolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Parameters = proposal.NewParameters
	delete(gpp.Governance.Proposals, proposalID)
	delete(gpp.Governance.Votes, proposalID)

	return nil
}

// GetPoolParameters retrieves the parameters of a specific liquidity pool
func (gpp *GovernancePoolParameters) GetPoolParameters(poolID common.Hash) (*PoolParameters, error) {
	gpp.Lock.Lock()
	defer gpp.Lock.Unlock()

	pool, exists := gpp.Pools[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	return pool.Parameters, nil
}

// ListPools lists all the governed liquidity pools
func (gpp *GovernancePoolParameters) ListPools() []*GovernedPool {
	gpp.Lock.Lock()
	defer gpp.Lock.Unlock()

	pools := []*GovernedPool{}
	for _, pool := range gpp.Pools {
		pools = append(pools, pool)
	}

	return pools
}

// UpdatePoolParameters updates the parameters of a specific liquidity pool directly (requires governance approval in real-world scenarios)
func (gpp *GovernancePoolParameters) UpdatePoolParameters(poolID common.Hash, newParameters *PoolParameters) error {
	gpp.Lock.Lock()
	defer gpp.Lock.Unlock()

	pool, exists := gpp.Pools[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Parameters = newParameters
	return nil
}

