package dynamic_parameter_adjustment

import (
    "sync"
    "time"
    "math/big"

    "github.com/synnergy_network/pkg/synnergy_network/core/consensus"
    "github.com/synnergy_network/pkg/synnergy_network/core/crypto"
    "github.com/synnergy_network/pkg/synnergy_network/core/network"
    "github.com/synnergy_network/pkg/synnergy_network/core/operations/utils"
    "github.com/synnergy_network/pkg/synnergy_network/core/operations/security_compliance"
)

type Parameter struct {
    Name        string
    Value       big.Int
    LastUpdated time.Time
}

type FeedbackLoop struct {
    Parameters   map[string]*Parameter
    mu           sync.Mutex
    consensus    *consensus.Consensus
    encryption   *security_compliance.EncryptionService
    feedbackChan chan FeedbackData
}

type FeedbackData struct {
    ParameterName string
    NewValue      big.Int
    Timestamp     time.Time
}

func NewFeedbackLoop(consensus *consensus.Consensus, encryption *security_compliance.EncryptionService) *FeedbackLoop {
    return &FeedbackLoop{
        Parameters:   make(map[string]*Parameter),
        consensus:    consensus,
        encryption:   encryption,
        feedbackChan: make(chan FeedbackData, 100),
    }
}

func (fl *FeedbackLoop) AddParameter(name string, value big.Int) {
    fl.mu.Lock()
    defer fl.mu.Unlock()

    fl.Parameters[name] = &Parameter{
        Name:        name,
        Value:       value,
        LastUpdated: time.Now(),
    }
}

func (fl *FeedbackLoop) UpdateParameter(name string, newValue big.Int) error {
    fl.mu.Lock()
    defer fl.mu.Unlock()

    param, exists := fl.Parameters[name]
    if !exists {
        return fmt.Errorf("parameter not found")
    }

    param.Value = newValue
    param.LastUpdated = time.Now()

    feedbackData := FeedbackData{
        ParameterName: name,
        NewValue:      newValue,
        Timestamp:     time.Now(),
    }
    fl.feedbackChan <- feedbackData

    return nil
}

func (fl *FeedbackLoop) MonitorFeedback() {
    for feedback := range fl.feedbackChan {
        encryptedData, err := fl.encryption.Encrypt([]byte(feedback.ParameterName + feedback.NewValue.String()))
        if err != nil {
            fmt.Printf("failed to encrypt feedback data: %v", err)
            continue
        }

        // Consensus mechanism to validate and apply the parameter update
        valid, err := fl.consensus.ValidateParameterUpdate(feedback.ParameterName, feedback.NewValue)
        if err != nil {
            fmt.Printf("failed to validate parameter update: %v", err)
            continue
        }

        if valid {
            fl.applyParameterUpdate(feedback.ParameterName, feedback.NewValue, encryptedData)
        }
    }
}

func (fl *FeedbackLoop) applyParameterUpdate(name string, newValue big.Int, encryptedData []byte) {
    fl.mu.Lock()
    defer fl.mu.Unlock()

    param, exists := fl.Parameters[name]
    if !exists {
        fmt.Printf("parameter %s not found", name)
        return
    }

    param.Value = newValue
    param.LastUpdated = time.Now()
    // Log the update for transparency
    fmt.Printf("parameter %s updated to %s at %v\n", name, newValue.String(), param.LastUpdated)
}

func (fl *FeedbackLoop) ListParameters() map[string]*Parameter {
    fl.mu.Lock()
    defer fl.mu.Unlock()

    params := make(map[string]*Parameter)
    for name, param := range fl.Parameters {
        params[name] = param
    }
    return params
}

func (fl *FeedbackLoop) GetParameter(name string) (*Parameter, error) {
    fl.mu.Lock()
    defer fl.mu.Unlock()

    param, exists := fl.Parameters[name]
    if !exists {
        return nil, fmt.Errorf("parameter not found")
    }

    return param, nil
}

func (fl *FeedbackLoop) ValidateFeedbackData(feedback FeedbackData) (bool, error) {
    decryptedData, err := fl.encryption.Decrypt([]byte(feedback.ParameterName + feedback.NewValue.String()))
    if err != nil {
        return false, fmt.Errorf("failed to decrypt feedback data: %v", err)
    }

    // Further validation logic can be implemented here
    return string(decryptedData) == feedback.ParameterName+feedback.NewValue.String(), nil
}
