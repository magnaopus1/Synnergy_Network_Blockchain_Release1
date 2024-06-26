package syn70

import (
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "sync"
    "time"

    "synthron-blockchain/pkg/common"
)

type Token struct {
    ID           string    `json:"id"`
    Name         string    `json:"name"`
    Owner        string    `json:"owner"`
    Balance      int64     `json:"balance"`
    GameID       string    `json:"game_id"`
    Attributes   map[string]int64  `json:"attributes"`
    Achievements []string  `json:"achievements"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
    mutex        sync.Mutex
    DB           *common.Database
}

func NewToken(id, name, owner, gameID string, db *common.Database) *Token {
    return &Token{
        ID:           id,
        Name:         name,
        Owner:        owner,
        GameID:       gameID,
        Balance:      0,
        Attributes:   make(map[string]int64),
        Achievements: make([]string, 0),
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
        DB:           db,
    }
}

func (t *Token) Credit(amount int64) {
    t.mutex.Lock()
    defer t.mutex.Unlock()
    t.Balance += amount
    t.UpdatedAt = time.Now()
    log.Printf("Credited %d to %s, new balance: %d", amount, t.ID, t.Balance)
}

func (t *Token) Debit(amount int64) error {
    t.mutex.Lock()
    defer t.mutex.Unlock()
    if amount > t.Balance {
        return fmt.Errorf("insufficient balance in token %s", t.ID)
    }
    t.Balance -= amount
    t.UpdatedAt = time.Now()
    log.Printf("Debited %d from %s, new balance: %d", amount, t.ID, t.Balance)
    return nil
}

func (t *Token) Transfer(recipientID string, amount int64) error {
    recipientToken, err := t.DB.GetTokenByID(recipientID)
    if err != nil {
        return fmt.Errorf("failed to transfer tokens: %v", err)
    }

    if err := t.Debit(amount); err != nil {
        return err
    }

    recipientToken.Credit(amount)
    log.Printf("Transferred %d from %s to %s", amount, t.ID, recipientToken.ID)
    return nil
}

func (t *Token) AddAchievement(achievement string) {
    t.mutex.Lock()
    defer t.mutex.Unlock()
    t.Achievements = append(t.Achievements, achievement)
    t.UpdatedAt = time.Now()
    log.Printf("Added achievement %s to token %s", achievement, t.ID)
}

func (t *Token) UpdateAttribute(attribute string, value int64) {
    t.mutex.Lock()
    defer t.mutex.Unlock()
    t.Attributes[attribute] = value
    t.UpdatedAt = time.Now()
    log.Printf("Updated attribute %s for token %s to %d", attribute, t.ID, value)
}

func (t *Token) Save() error {
    return t.DB.SaveToken(t)
}

func (t *Token) MarshalJSON() ([]byte, error) {
    return json.Marshal(struct {
        ID           string            `json:"id"`
        Name         string            `json:"name"`
        Owner        string            `json:"owner"`
        Balance      int64             `json:"balance"`
        GameID       string            `json:"game_id"`
        Attributes   map[string]int64  `json:"attributes"`
        Achievements []string          `json:"achievements"`
        CreatedAt    time.Time         `json:"created_at"`
        UpdatedAt    time.Time         `json:"updated_at"`
    }{
        ID:           t.ID,
        Name:         t.Name,
        Owner:        t.Owner,
        Balance:      t.Balance,
        GameID:       t.GameID,
        Attributes:   t.Attributes,
        Achievements: t.Achievements,
        CreatedAt:    t.CreatedAt,
        UpdatedAt:    t.UpdatedAt,
    })
}
