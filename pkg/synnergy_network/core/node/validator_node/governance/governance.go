package governance

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/common"
)

type Governance struct {
	NodeID           string
	VoteWeight       float64
	ProposalEndpoint string
	VotingEndpoint   string
}

type Proposal struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Status    string `json:"status"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

type Vote struct {
	ProposalID string `json:"proposal_id"`
	NodeID     string `json:"node_id"`
	VoteWeight float64 `json:"vote_weight"`
	Decision   string `json:"decision"` // "yes", "no", "abstain"
	Timestamp  time.Time `json:"timestamp"`
}

func (g *Governance) Initialize(nodeID string, voteWeight float64, proposalEndpoint, votingEndpoint string) {
	g.NodeID = nodeID
	g.VoteWeight = voteWeight
	g.ProposalEndpoint = proposalEndpoint
	g.VotingEndpoint = votingEndpoint
}

func (g *Governance) FetchProposals() ([]Proposal, error) {
	resp, err := http.Get(g.ProposalEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var proposals []Proposal
	if err := json.NewDecoder(resp.Body).Decode(&proposals); err != nil {
		return nil, err
	}
	return proposals, nil
}

func (g *Governance) VoteOnProposal(proposalID, decision string) error {
	vote := Vote{
		ProposalID: proposalID,
		NodeID:     g.NodeID,
		VoteWeight: g.VoteWeight,
		Decision:   decision,
		Timestamp:  time.Now(),
	}

	voteData, err := json.Marshal(vote)
	if err != nil {
		return err
	}

	resp, err := http.Post(g.VotingEndpoint, "application/json", bytes.NewBuffer(voteData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to submit vote")
	}

	return nil
}

func (g *Governance) CheckProposalStatus(proposalID string) (string, error) {
	proposals, err := g.FetchProposals()
	if err != nil {
		return "", err
	}

	for _, proposal := range proposals {
		if proposal.ID == proposalID {
			return proposal.Status, nil
		}
	}
	return "", errors.New("proposal not found")
}

func (g *Governance) ParticipateInGovernance() {
	for {
		time.Sleep(24 * time.Hour)
		proposals, err := g.FetchProposals()
		if err != nil {
			log.Printf("Error fetching proposals: %v", err)
			continue
		}

		for _, proposal := range proposals {
			if proposal.Status == "open" {
				decision := g.MakeDecision(proposal)
				if err := g.VoteOnProposal(proposal.ID, decision); err != nil {
					log.Printf("Error voting on proposal %s: %v", proposal.ID, err)
				} else {
					log.Printf("Voted %s on proposal %s", decision, proposal.ID)
				}
			}
		}
	}
}

func (g *Governance) MakeDecision(proposal Proposal) string {
	// Implement decision-making logic here
	// This can be based on various factors such as proposal content, current network state, etc.
	// For now, we will just vote "yes" on every proposal as a placeholder
	return "yes"
}