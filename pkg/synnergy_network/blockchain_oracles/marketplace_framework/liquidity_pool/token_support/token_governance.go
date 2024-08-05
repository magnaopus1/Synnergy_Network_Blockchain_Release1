package token_support

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/scrypt"
)

// GovernanceToken represents a governance token with its details
type GovernanceToken struct {
	Symbol   string
	Name     string
	Decimals int
	Address  common.Address
}

// GovernanceProposal represents a proposal for governance
type GovernanceProposal struct {
	ProposalID    string
	Title         string
	Description   string
	Proposer      common.Address
	VotesFor      decimal.Decimal
	VotesAgainst  decimal.Decimal
	DeadlineBlock int64
}

// TokenGovernanceManager manages token governance
type TokenGovernanceManager struct {
	Tokens     map[string]GovernanceToken
	Proposals  map[string]GovernanceProposal
	VoteLedger map[string]map[common.Address]bool // Tracks if an address has voted on a proposal
	Lock       sync.Mutex
}

// NewTokenGovernanceManager creates a new TokenGovernanceManager instance
func NewTokenGovernanceManager() *TokenGovernanceManager {
	return &TokenGovernanceManager{
		Tokens:     make(map[string]GovernanceToken),
		Proposals:  make(map[string]GovernanceProposal),
		VoteLedger: make(map[string]map[common.Address]bool),
	}
}

// AddGovernanceToken adds a new governance token to the manager
func (tgm *TokenGovernanceManager) AddGovernanceToken(symbol, name string, decimals int, address common.Address) error {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	if _, exists := tgm.Tokens[symbol]; exists {
		return errors.New("governance token already exists")
	}

	token := GovernanceToken{
		Symbol:   symbol,
		Name:     name,
		Decimals: decimals,
		Address:  address,
	}

	tgm.Tokens[symbol] = token
	return nil
}

// RemoveGovernanceToken removes a governance token from the manager
func (tgm *TokenGovernanceManager) RemoveGovernanceToken(symbol string) error {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	if _, exists := tgm.Tokens[symbol]; !exists {
		return errors.New("governance token not found")
	}

	delete(tgm.Tokens, symbol)
	return nil
}

// CreateProposal creates a new governance proposal
func (tgm *TokenGovernanceManager) CreateProposal(title, description string, proposer common.Address, deadlineBlock int64) (GovernanceProposal, error) {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	proposalID, err := generateProposalID(title, proposer, deadlineBlock)
	if err != nil {
		return GovernanceProposal{}, err
	}

	proposal := GovernanceProposal{
		ProposalID:    proposalID,
		Title:         title,
		Description:   description,
		Proposer:      proposer,
		VotesFor:      decimal.NewFromInt(0),
		VotesAgainst:  decimal.NewFromInt(0),
		DeadlineBlock: deadlineBlock,
	}

	tgm.Proposals[proposalID] = proposal
	tgm.VoteLedger[proposalID] = make(map[common.Address]bool)
	return proposal, nil
}

// VoteOnProposal allows a token holder to vote on a proposal
func (tgm *TokenGovernanceManager) VoteOnProposal(proposalID string, voter common.Address, votes decimal.Decimal, support bool) error {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	proposal, exists := tgm.Proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if _, hasVoted := tgm.VoteLedger[proposalID][voter]; hasVoted {
		return errors.New("voter has already voted on this proposal")
	}

	if support {
		proposal.VotesFor = proposal.VotesFor.Add(votes)
	} else {
		proposal.VotesAgainst = proposal.VotesAgainst.Add(votes)
	}

	tgm.Proposals[proposalID] = proposal
	tgm.VoteLedger[proposalID][voter] = true
	return nil
}

// GetProposal retrieves a governance proposal by its ID
func (tgm *TokenGovernanceManager) GetProposal(proposalID string) (GovernanceProposal, error) {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	proposal, exists := tgm.Proposals[proposalID]
	if !exists {
		return GovernanceProposal{}, errors.New("proposal not found")
	}

	return proposal, nil
}

// generateProposalID generates a unique proposal ID
func generateProposalID(title string, proposer common.Address, deadlineBlock int64) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s-%d-%s", title, proposer.Hex(), deadlineBlock, hex.EncodeToString(randBytes))))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ListAllGovernanceTokens lists all governance tokens managed by the TokenGovernanceManager
func (tgm *TokenGovernanceManager) ListAllGovernanceTokens() []GovernanceToken {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	tokens := []GovernanceToken{}
	for _, token := range tgm.Tokens {
		tokens = append(tokens, token)
	}
	return tokens
}

// ListAllProposals lists all proposals managed by the TokenGovernanceManager
func (tgm *TokenGovernanceManager) ListAllProposals() []GovernanceProposal {
	tgm.Lock.Lock()
	defer tgm.Lock.Unlock()

	proposals := []GovernanceProposal{}
	for _, proposal := range tgm.Proposals {
		proposals = append(proposals, proposal)
	}
	return proposals
}

// generateSalt generates a random salt for hashing
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// hashPassword hashes a password using scrypt with a salt
func hashPassword(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}
