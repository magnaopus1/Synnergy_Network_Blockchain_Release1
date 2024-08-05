package decentralized

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// VoteStatus represents the status of a stakeholder vote
type VoteStatus int

const (
    Pending VoteStatus = iota
    Approved
    Rejected
)

// StakeholderVote represents a vote in the governance model
type StakeholderVote struct {
    ID            string
    ProposalID    string
    VoterID       string
    VoteFor       bool
    Status        VoteStatus
    Timestamp     time.Time
    EncryptedData string
}

// StakeholderVoting manages stakeholder votes on proposals
type StakeholderVoting struct {
    Votes  map[string]StakeholderVote
    Proposals map[string]GovernanceProposal
    mutex  sync.Mutex
}

// NewStakeholderVoting initializes a new StakeholderVoting
func NewStakeholderVoting() *StakeholderVoting {
    return &StakeholderVoting{
        Votes:  make(map[string]StakeholderVote),
        Proposals: make(map[string]GovernanceProposal),
    }
}

// SubmitVote allows a stakeholder to submit a vote on a proposal
func (sv *StakeholderVoting) SubmitVote(proposalID, voterID string, voteFor bool, secret string) (string, error) {
    sv.mutex.Lock()
    defer sv.mutex.Unlock()

    if _, exists := sv.Proposals[proposalID]; !exists {
        return "", errors.New("proposal does not exist")
    }

    id := uuid.New().String()
    data := fmt.Sprintf("%s:%s:%t", proposalID, voterID, voteFor)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }

    vote := StakeholderVote{
        ID:            id,
        ProposalID:    proposalID,
        VoterID:       voterID,
        VoteFor:       voteFor,
        Status:        Pending,
        Timestamp:     time.Now(),
        EncryptedData: encryptedData,
    }
    sv.Votes[id] = vote
    return id, nil
}

// ValidateVote validates and finalizes a vote
func (sv *StakeholderVoting) ValidateVote(voteID, secret string) error {
    sv.mutex.Lock()
    defer sv.mutex.Unlock()

    vote, exists := sv.Votes[voteID]
    if !exists {
        return errors.New("vote does not exist")
    }

    decryptedData, err := decryptData(secret, vote.EncryptedData)
    if err != nil {
        return err
    }

    if vote.Status != Pending {
        return errors.New("vote already validated")
    }

    proposal, exists := sv.Proposals[vote.ProposalID]
    if !exists {
        return errors.New("proposal does not exist")
    }

    if decryptedData == fmt.Sprintf("%s:%s:%t", vote.ProposalID, vote.VoterID, vote.VoteFor) {
        if vote.VoteFor {
            proposal.VotesFor++
        } else {
            proposal.VotesAgainst++
        }
        vote.Status = Approved
    } else {
        vote.Status = Rejected
    }

    sv.Proposals[vote.ProposalID] = proposal
    sv.Votes[voteID] = vote
    return nil
}

// ListVotes lists all votes for a specific proposal
func (sv *StakeholderVoting) ListVotes(proposalID string) ([]StakeholderVote, error) {
    sv.mutex.Lock()
    defer sv.mutex.Unlock()

    if _, exists := sv.Proposals[proposalID]; !exists {
        return nil, errors.New("proposal does not exist")
    }

    votes := []StakeholderVote{}
    for _, vote := range sv.Votes {
        if vote.ProposalID == proposalID {
            votes = append(votes, vote)
        }
    }
    return votes, nil
}

// encryptData encrypts the given data using AES
func encryptData(secret, data string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(encrypted), nil
}

// decryptData decrypts the given data using AES
func decryptData(secret, encryptedData string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(decrypted), nil
}

// createHash creates a hash from the secret key
func createHash(key string) string {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}

// generateSignature generates a signature for the vote using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
