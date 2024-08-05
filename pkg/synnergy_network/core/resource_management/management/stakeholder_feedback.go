// Package management handles stakeholder feedback collection and analysis for the Synnergy Network.
package management

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "sync"
    "time"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "io"
)

// FeedbackType defines the types of feedback that can be provided
type FeedbackType string

const (
    FeedbackBugReport  FeedbackType = "BUG_REPORT"
    FeedbackFeatureReq FeedbackType = "FEATURE_REQUEST"
    FeedbackGeneral    FeedbackType = "GENERAL_FEEDBACK"
)

// Feedback represents a single feedback entry from a stakeholder
type Feedback struct {
    Timestamp    time.Time   `json:"timestamp"`
    UserID       string      `json:"user_id"`
    Type         FeedbackType `json:"type"`
    Description  string      `json:"description"`
    IsAnonymous  bool        `json:"is_anonymous"`
}

// FeedbackManager handles the collection, storage, and analysis of stakeholder feedback
type FeedbackManager struct {
    feedbacks   []Feedback
    dataMutex   sync.Mutex
    encryptionKey []byte
}

// NewFeedbackManager initializes a new FeedbackManager with a given encryption key
func NewFeedbackManager(encryptionKey string) *FeedbackManager {
    return &FeedbackManager{
        feedbacks:   []Feedback{},
        encryptionKey: sha256.Sum256([]byte(encryptionKey)),
    }
}

// CollectFeedback collects feedback and stores it securely
func (fm *FeedbackManager) CollectFeedback(userID string, fType FeedbackType, description string, isAnonymous bool) {
    fm.dataMutex.Lock()
    defer fm.dataMutex.Unlock()

    feedback := Feedback{
        Timestamp:   time.Now(),
        UserID:      userID,
        Type:        fType,
        Description: description,
        IsAnonymous: isAnonymous,
    }
    encryptedFeedback, err := fm.encryptFeedback(feedback)
    if err != nil {
        log.Printf("Error encrypting feedback: %v", err)
        return
    }
    fm.feedbacks = append(fm.feedbacks, encryptedFeedback)
    log.Printf("Collected feedback: %v", feedback)
}

// encryptFeedback encrypts feedback data using AES encryption
func (fm *FeedbackManager) encryptFeedback(feedback Feedback) (Feedback, error) {
    plaintext, err := json.Marshal(feedback)
    if err != nil {
        return feedback, err
    }

    block, err := aes.NewCipher(fm.encryptionKey[:])
    if err != nil {
        return feedback, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return feedback, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    feedback.Description = string(ciphertext)
    return feedback, nil
}

// decryptFeedback decrypts feedback data
func (fm *FeedbackManager) decryptFeedback(feedback Feedback) (Feedback, error) {
    ciphertext := []byte(feedback.Description)
    block, err := aes.NewCipher(fm.encryptionKey[:])
    if err != nil {
        return feedback, err
    }

    if len(ciphertext) < aes.BlockSize {
        return feedback, fmt.Errorf("ciphertext too short")
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    var decryptedFeedback Feedback
    if err := json.Unmarshal(ciphertext, &decryptedFeedback); err != nil {
        return feedback, err
    }

    return decryptedFeedback, nil
}

// AnalyzeFeedback analyzes collected feedback for actionable insights
func (fm *FeedbackManager) AnalyzeFeedback() map[FeedbackType]int {
    fm.dataMutex.Lock()
    defer fm.dataMutex.Unlock()

    analysis := make(map[FeedbackType]int)
    for _, feedback := range fm.feedbacks {
        decryptedFeedback, err := fm.decryptFeedback(feedback)
        if err != nil {
            log.Printf("Error decrypting feedback: %v", err)
            continue
        }
        analysis[decryptedFeedback.Type]++
    }
    return analysis
}

// SaveFeedbackToFile saves the collected feedback to a JSON file
func (fm *FeedbackManager) SaveFeedbackToFile(filename string) error {
    fm.dataMutex.Lock()
    defer fm.dataMutex.Unlock()

    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    return encoder.Encode(fm.feedbacks)
}

// LoadFeedbackFromFile loads feedback from a JSON file
func (fm *FeedbackManager) LoadFeedbackFromFile(filename string) error {
    fm.dataMutex.Lock()
    defer fm.dataMutex.Unlock()

    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    return decoder.Decode(&fm.feedbacks)
}
