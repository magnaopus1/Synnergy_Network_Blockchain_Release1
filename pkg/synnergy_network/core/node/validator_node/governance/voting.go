package governance

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/common"
)

type Voting struct {
	NodeID           string
	VoteWeight       float64
	ProposalEndpoint string
	VotingEndpoint   string
}

type Proposal struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
}

type Vote struct {
	ProposalID string    `json:"proposal_id"`
	NodeID     string    `json:"node_id"`
	VoteWeight float64   `json:"vote_weight"`
	Decision   string    `json:"decision"` // "yes", "no", "abstain"
	Timestamp  time.Time `json:"timestamp"`
}

func (v *Voting) Initialize(nodeID string, voteWeight float64, proposalEndpoint, votingEndpoint string) {
	v.NodeID = nodeID
	v.VoteWeight = voteWeight
	v.ProposalEndpoint = proposalEndpoint
	v.VotingEndpoint = votingEndpoint
}

func (v *Voting) FetchProposals() ([]Proposal, error) {
	resp, err := http.Get(v.ProposalEndpoint)
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

func (v *Voting) VoteOnProposal(proposalID, decision string) error {
	vote := Vote{
		ProposalID: proposalID,
		NodeID:     v.NodeID,
		VoteWeight: v.VoteWeight,
		Decision:   decision,
		Timestamp:  time.Now(),
	}

	voteData, err := json.Marshal(vote)
	if err != nil {
		return err
	}

	resp, err := http.Post(v.VotingEndpoint, "application/json", bytes.NewBuffer(voteData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to submit vote")
	}

	return nil
}

func (v *Voting) CheckProposalStatus(proposalID string) (string, error) {
	proposals, err := v.FetchProposals()
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

func (v *Voting) ParticipateInVoting() {
	for {
		time.Sleep(24 * time.Hour)
		proposals, err := v.FetchProposals()
		if err != nil {
			log.Printf("Error fetching proposals: %v", err)
			continue
		}

		for _, proposal := range proposals {
			if proposal.Status == "open" {
				decision := v.MakeDecision(proposal)
				if err := v.VoteOnProposal(proposal.ID, decision); err != nil {
					log.Printf("Error voting on proposal %s: %v", proposal.ID, err)
				} else {
					log.Printf("Voted %s on proposal %s", decision, proposal.ID)
				}
			}
		}
	}
}

func (v *Voting) MakeDecision(proposal Proposal) string {
	// Implement decision-making logic here
	// This can be based on various factors such as proposal content, current network state, etc.
	// For now, we will just vote "yes" on every proposal as a placeholder
	return "yes"
}

// Encrypts data using AES encryption
func EncryptData(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// Decrypts data using AES encryption
func DecryptData(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

