package syn700

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"
)

// IPAsset represents the details of the intellectual property associated with the token.
type IPAsset struct {
    Title       string
    Description string
    Creator     string
    Registered  time.Time
    Licenses    []LicenseDetail
}

// LicenseDetail represents licensing agreements linked to the token.
type LicenseDetail struct {
    Licensee    string
    LicenseType string
    ValidUntil  time.Time
}

// Token represents an intellectual property token on the Synthron Blockchain.
type Token struct {
    ID          string
    Owner       string
    IP          IPAsset
    Royalties   map[string]float64 // Maps user addresses to their royalty percentages
    mutex       sync.Mutex
    Transfers   []TransferLog
    EditHistory []EditLog // Tracks changes made to the token's IP details
}

// TransferLog records the details of ownership transfers.
type TransferLog struct {
    From        string
    To          string
    Date        time.Time
}

// EditLog records the details of edits made to the token's properties.
type EditLog struct {
    EditedBy    string
    EditDate    time.Time
    Detail      string
}

// NewToken initializes a new intellectual property token.
func NewToken(id, owner string, ip IPAsset) *Token {
    return &Token{
        ID:         id,
        Owner:      owner,
        IP:         ip,
        Royalties:  make(map[string]float64),
        Transfers:  []TransferLog{},
        EditHistory: []EditLog{},
    }
}

// RegisterLicense adds a licensing agreement to the IPAsset.
func (t *Token) RegisterLicense(licensee, licenseType string, duration time.Duration) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    newLicense := LicenseDetail{
        Licensee:    licensee,
        LicenseType: licenseType,
        ValidUntil:  time.Now().Add(duration),
    }
    t.IP.Licenses = append(t.IP.Licenses, newLicense)
    t.logEdit(fmt.Sprintf("Added new license: %s for %s, valid until %s", licenseType, licensee, newLicense.ValidUntil))
    return nil
}

// UpdateIPDetails allows the owner to modify the intellectual property details.
func (t *Token) UpdateIPDetails(newTitle, newDescription string, editor string) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()

    t.IP.Title = newTitle
    t.IP.Description = newDescription
    t.logEdit(fmt.Sprintf("IP details updated by %s", editor))
    return nil
}

// logEdit logs the details of edits made to the token.
func (t *Token) logEdit(detail string) {
    newLog := EditLog{
        EditedBy: t.Owner,
        EditDate: time.Now(),
        Detail:   detail,
    }
    t.EditHistory = append(t.EditHistory, newLog)
    log.Println(detail)
}

// generateTokenID creates a unique ID for a new token based on IP details.
func generateTokenID(ip IPAsset) string {
    data := fmt.Sprintf("%s:%s:%s:%d", ip.Title, ip.Creator, ip.Registered.String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
