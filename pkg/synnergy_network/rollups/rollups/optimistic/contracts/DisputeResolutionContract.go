package contracts

import (
    "crypto/sha256"
    "encoding/json"
    "errors"
    "sync"
    "time"
    "crypto/rand"
    "fmt"
    "golang.org/x/crypto/scrypt"
    "github.com/minio/sio"
)

// DisputeResolutionContract manages dispute resolutions within the optimistic rollup.
type DisputeResolutionContract struct {
    disputes   map[string]*Dispute
    mutex      sync.Mutex
}

// Dispute represents a single dispute within the system.
type Dispute struct {
    ID             string
    FromRollup     string
    ToRollup       string
    Description    string
    Evidence       string
    Status         string
    Timestamp      time.Time
    Resolution     string
    Signature      []byte
}

// NewDisputeResolutionContract initializes a new DisputeResolutionContract.
func NewDisputeResolutionContract() *DisputeResolutionContract {
    return &DisputeResolutionContract{
        disputes: make(map[string]*Dispute),
    }
}

// FileDispute allows a rollup to file a dispute against another rollup.
func (drc *DisputeResolutionContract) FileDispute(fromRollup, toRollup, description, evidence string) (string, error) {
    drc.mutex.Lock()
    defer drc.mutex.Unlock()

    id := generateID()
    dispute := &Dispute{
        ID:          id,
        FromRollup:  fromRollup,
        ToRollup:    toRollup,
        Description: description,
        Evidence:    evidence,
        Status:      "Pending",
        Timestamp:   time.Now(),
    }

    // Sign the dispute
    signature, err := drc.signDispute(dispute)
    if err != nil {
        return "", err
    }
    dispute.Signature = signature

    // Encrypt the evidence
    encryptedEvidence, err := encryptContent(dispute.Evidence)
    if err != nil {
        return "", err
    }
    dispute.Evidence = encryptedEvidence

    drc.disputes[id] = dispute
    return id, nil
}

// ResolveDispute allows an authorized entity to resolve a dispute.
func (drc *DisputeResolutionContract) ResolveDispute(id, resolution string) error {
    drc.mutex.Lock()
    defer drc.mutex.Unlock()

    dispute, exists := drc.disputes[id]
    if !exists {
        return errors.New("dispute does not exist")
    }

    // Decrypt the evidence
    decryptedEvidence, err := decryptContent(dispute.Evidence)
    if err != nil {
        return err
    }
    dispute.Evidence = decryptedEvidence

    dispute.Status = "Resolved"
    dispute.Resolution = resolution
    return nil
}

// ListPendingDisputes lists all pending disputes.
func (drc *DisputeResolutionContract) ListPendingDisputes() []*Dispute {
    drc.mutex.Lock()
    defer drc.mutex.Unlock()

    var pendingDisputes []*Dispute
    for _, dispute := range drc.disputes {
        if dispute.Status == "Pending" {
            pendingDisputes = append(pendingDisputes, dispute)
        }
    }
    return pendingDisputes
}

// GetDispute retrieves a dispute by its ID.
func (drc *DisputeResolutionContract) GetDispute(id string) (*Dispute, error) {
    drc.mutex.Lock()
    defer drc.mutex.Unlock()

    dispute, exists := drc.disputes[id]
    if !exists {
        return nil, errors.New("dispute does not exist")
    }
    return dispute, nil
}

// signDispute signs a dispute.
func (drc *DisputeResolutionContract) signDispute(dispute *Dispute) ([]byte, error) {
    disputeData, err := json.Marshal(dispute)
    if err != nil {
        return nil, err
    }

    hash := sha256.Sum256(disputeData)
    signature := hash[:]
    return signature, nil
}

// encryptContent encrypts the content using Scrypt/AES.
func encryptContent(content string) (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(content), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    encryptedContent, err := sio.EncryptReader(rand.Reader, sio.Config{Key: key})
    if err != nil {
        return "", err
    }

    return string(encryptedContent), nil
}

// decryptContent decrypts the content using Scrypt/AES.
func decryptContent(content string) (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(content), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    decryptedContent, err := sio.DecryptReader(rand.Reader, sio.Config{Key: key})
    if err != nil {
        return "", err
    }

    return string(decryptedContent), nil
}

// generateID generates a unique ID for a dispute.
func generateID() string {
    return fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))
}
