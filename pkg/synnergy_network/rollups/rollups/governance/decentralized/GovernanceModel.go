package decentralized

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// ProposalStatus represents the status of a governance proposal
type ProposalStatus int

const (
    Pending ProposalStatus = iota
    Approved
    Rejected
)

// GovernanceProposal represents a proposal in the governance model
type GovernanceProposal struct {
    ID             string
    Title          string
    Description    string
    Proposer       string
    VotesFor       int
    VotesAgainst   int
    Status         ProposalStatus
    Timestamp      time.Time
    EncryptedData  string
}

// GovernanceModel manages governance proposals and voting
type GovernanceModel struct {
    Proposals map[string]GovernanceProposal
    mutex     sync.Mutex
}

// NewGovernanceModel initializes a new GovernanceModel
func NewGovernanceModel() *GovernanceModel {
    return &GovernanceModel{
        Proposals: make(map[string]GovernanceProposal),
    }
}

// CreateProposal creates a new governance proposal with encryption
func (gm *GovernanceModel) CreateProposal(title, description, proposer, secret string) (string, error) {
    gm.mutex.Lock()
    defer gm.mutex.Unlock()

    id := uuid.New().String()
    data := fmt.Sprintf("%s:%s:%s", title, description, proposer)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }

    proposal := GovernanceProposal{
        ID:            id,
        Title:         title,
        Description:   description,
        Proposer:      proposer,
        VotesFor:      0,
        VotesAgainst:  0,
        Status:        Pending,
        Timestamp:     time.Now(),
        EncryptedData: encryptedData,
    }
    gm.Proposals[id] = proposal
    return id, nil
}

// VoteProposal allows voting on a governance proposal
func (gm *GovernanceModel) VoteProposal(id, voter string, voteFor bool) error {
    gm.mutex.Lock()
    defer gm.mutex.Unlock()

    proposal, exists := gm.Proposals[id]
    if !exists {
        return errors.New("proposal does not exist")
    }

    if voteFor {
        proposal.VotesFor++
    } else {
        proposal.VotesAgainst++
    }

    gm.Proposals[id] = proposal
    return nil
}

// FinalizeProposal finalizes the voting on a governance proposal
func (gm *GovernanceModel) FinalizeProposal(id string) error {
    gm.mutex.Lock()
    defer gm.mutex.Unlock()

    proposal, exists := gm.Proposals[id]
    if !exists {
        return errors.New("proposal does not exist")
    }

    if proposal.VotesFor > proposal.VotesAgainst {
        proposal.Status = Approved
    } else {
        proposal.Status = Rejected
    }

    gm.Proposals[id] = proposal
    return nil
}

// GetProposal retrieves a governance proposal by ID and decrypts it
func (gm *GovernanceModel) GetProposal(id, secret string) (GovernanceProposal, error) {
    gm.mutex.Lock()
    defer gm.mutex.Unlock()

    proposal, exists := gm.Proposals[id]
    if !exists {
        return GovernanceProposal{}, errors.New("proposal does not exist")
    }

    decryptedData, err := decryptData(secret, proposal.EncryptedData)
    if err != nil {
        return GovernanceProposal{}, err
    }

    proposal.EncryptedData = decryptedData
    return proposal, nil
}

// ListProposals lists all governance proposals
func (gm *GovernanceModel) ListProposals() []GovernanceProposal {
    gm.mutex.Lock()
    defer gm.mutex.Unlock()

    proposals := []GovernanceProposal{}
    for _, proposal := range gm.Proposals {
        proposals = append(proposals, proposal)
    }
    return proposals
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

// generateSignature generates a signature for the proposal using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
