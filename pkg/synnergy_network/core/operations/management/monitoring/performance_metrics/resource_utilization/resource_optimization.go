package resource_utilization

import (
    "context"
    "fmt"
    "log"
    "math"
    "sync"
    "time"

    "github.com/synnergy_network/blockchain"
    "github.com/synnergy_network/core/utils"
    "github.com/synnergy_network/monitoring"
    "github.com/synnergy_network/encryption"
    "github.com/synnergy_network/predictive_maintenance"
)

const (
    OptimizationInterval = 5 * time.Minute
    ResourceThreshold    = 0.8
)

type ResourceOptimizer struct {
    blockchainClient     *blockchain.Client
    monitoringService    *monitoring.Service
    encryptionService    *encryption.Service
    predictiveService    *predictive_maintenance.Service
    mu                   sync.Mutex
    resourceUtilization  map[string]float64
    optimizationInterval time.Duration
    resourceThreshold    float64
}

func NewResourceOptimizer(bcClient *blockchain.Client, monitorSvc *monitoring.Service, encryptSvc *encryption.Service, predictSvc *predictive_maintenance.Service) *ResourceOptimizer {
    return &ResourceOptimizer{
        blockchainClient:     bcClient,
        monitoringService:    monitorSvc,
        encryptionService:    encryptSvc,
        predictiveService:    predictSvc,
        resourceUtilization:  make(map[string]float64),
        optimizationInterval: OptimizationInterval,
        resourceThreshold:    ResourceThreshold,
    }
}

func (ro *ResourceOptimizer) Start(ctx context.Context) {
    ticker := time.NewTicker(ro.optimizationInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            ro.optimizeResources()
        }
    }
}

func (ro *ResourceOptimizer) optimizeResources() {
    ro.mu.Lock()
    defer ro.mu.Unlock()

    nodes, err := ro.blockchainClient.GetNodes()
    if err != nil {
        log.Printf("Error getting nodes: %v", err)
        return
    }

    for _, node := range nodes {
        utilization, err := ro.monitoringService.GetResourceUtilization(node.ID)
        if err != nil {
            log.Printf("Error getting resource utilization for node %s: %v", node.ID, err)
            continue
        }

        ro.resourceUtilization[node.ID] = utilization

        if utilization > ro.resourceThreshold {
            ro.scaleOut(node)
        } else if utilization < ro.resourceThreshold/2 {
            ro.scaleIn(node)
        }
    }

    ro.optimizeBasedOnPredictions()
}

func (ro *ResourceOptimizer) scaleOut(node blockchain.Node) {
    err := ro.blockchainClient.AddNode(node)
    if err != nil {
        log.Printf("Error scaling out node %s: %v", node.ID, err)
        return
    }
    log.Printf("Scaled out node %s", node.ID)
}

func (ro *ResourceOptimizer) scaleIn(node blockchain.Node) {
    err := ro.blockchainClient.RemoveNode(node)
    if err != nil {
        log.Printf("Error scaling in node %s: %v", node.ID, err)
        return
    }
    log.Printf("Scaled in node %s", node.ID)
}

func (ro *ResourceOptimizer) optimizeBasedOnPredictions() {
    predictions, err := ro.predictiveService.GetPredictedResourceUtilization()
    if err != nil {
        log.Printf("Error getting resource utilization predictions: %v", err)
        return
    }

    for nodeID, predictedUtilization := range predictions {
        if predictedUtilization > ro.resourceThreshold {
            node := ro.blockchainClient.GetNodeByID(nodeID)
            ro.scaleOut(node)
        } else if predictedUtilization < ro.resourceThreshold/2 {
            node := ro.blockchainClient.GetNodeByID(nodeID)
            ro.scaleIn(node)
        }
    }
}

func (ro *ResourceOptimizer) EncryptSensitiveData(data []byte) ([]byte, error) {
    salt := utils.GenerateSalt()
    encryptedData, err := ro.encryptionService.Encrypt(data, salt)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt data: %w", err)
    }
    return encryptedData, nil
}

func (ro *ResourceOptimizer) DecryptSensitiveData(encryptedData []byte, salt []byte) ([]byte, error) {
    decryptedData, err := ro.encryptionService.Decrypt(encryptedData, salt)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt data: %w", err)
    }
    return decryptedData, nil
}

func (ro *ResourceOptimizer) LogOptimizationActivity(activity string) {
    logData := fmt.Sprintf("Optimization activity: %s at %s", activity, time.Now().Format(time.RFC3339))
    encryptedLog, err := ro.EncryptSensitiveData([]byte(logData))
    if err != nil {
        log.Printf("Error encrypting log data: %v", err)
        return
    }
    ro.blockchainClient.LogActivity(encryptedLog)
}
