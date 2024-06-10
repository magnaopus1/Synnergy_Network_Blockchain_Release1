package governance_framework

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "io"
    "log"

    "github.com/pkg/errors"
)

// VotingMechanism defines the structure for different voting systems
type VotingMechanism struct {
    MechanismType string
    Parameters    map[string]interface{}
}

// VotingSystem encapsulates a voting method with associated encryption and validation mechanisms
type VotingSystem struct {
    SystemType string
    Mechanism  VotingMechanism
    PublicKey  []byte
    PrivateKey []byte
}

// NewVotingSystem initializes a new voting system with specified encryption keys
func NewVotingSystem(systemType string, mechanismType string, pubKey, privKey []byte) *VotingSystem {
    return &VotingSystem{
        SystemType: systemType,
        Mechanism: VotingMechanism{
            MechanismType: mechanismType,
            Parameters:    make(map[string]interface{}),
        },
        PublicKey:  pubKey,
        PrivateKey: privKey,
    }
}

// ConfigureParameters sets or updates parameters specific to the voting mechanism
func (vs *VotingSystem) ConfigureParameters(params map[string]interface{}) {
    for key, value := range params {
        vs.Mechanism.Parameters[key] = value
    }
    log.Printf("Parameters updated for %s", vs.SystemType)
}

// EncryptVote encrypts a vote using AES-256 GCM for secure transmission
func (vs *VotingSystem) EncryptVote(vote interface{}) ([]byte, error) {
    voteData, err := json.Marshal(vote)
    if err != nil {
        return nil, errors.Wrap(err, "failed to marshal vote")
    }

    block, err := aes.NewCipher(vs.PrivateKey)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create cipher block")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create GCM")
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, errors.Wrap(err, "failed to create nonce")
    }

    encryptedData := gcm.Seal(nonce, nonce, voteData, nil)
    return encryptedData, nil
}

// DecryptVote decrypts a vote for counting
func (vs *VotingSystem) DecryptVote(encryptedData []byte) (interface{}, error) {
    block, err := aes.NewCipher(vs.PrivateKey)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create cipher block")
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create GCM")
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return nil, errors.New("encrypted data is too short")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    voteData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, errors.Wrap(err, "failed to decrypt data")
    }

    var vote interface{}
    if err = json.Unmarshal(voteData, &vote); err != nil {
        return nil, errors.Wrap(err, "failed to unmarshal vote data")
    }

    return vote, nil
}

// ValidateVote ensures that a vote is valid according to the mechanism's rules
func (vs *VotingSystem) ValidateVote(vote interface{}) bool {
    // Implementation of validation logic based on mechanism's parameters
    // This is a placeholder for actual validation logic.
    return true
}
