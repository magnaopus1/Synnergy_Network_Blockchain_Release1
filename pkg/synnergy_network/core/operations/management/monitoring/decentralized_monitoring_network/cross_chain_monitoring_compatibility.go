package decentralized_monitoring_network

import (
    "fmt"
    "log"
    "time"
    "sync"

    "github.com/synnergy_network/utils"
    "github.com/synnergy_network/core/encryption"
    "github.com/synnergy_network/core/blockchain"
)

// CrossChainMonitoring handles monitoring activities across multiple blockchains
type CrossChainMonitoring struct {
    chains       []blockchain.Blockchain
    monitoringWG sync.WaitGroup
}

// NewCrossChainMonitoring initializes a new CrossChainMonitoring instance
func NewCrossChainMonitoring(chains []blockchain.Blockchain) *CrossChainMonitoring {
    return &CrossChainMonitoring{
        chains: chains,
    }
}

// StartMonitoring begins the monitoring process across all blockchains
func (ccm *CrossChainMonitoring) StartMonitoring() {
    for _, chain := range ccm.chains {
        ccm.monitoringWG.Add(1)
        go ccm.monitorChain(chain)
    }
    ccm.monitoringWG.Wait()
}

// monitorChain monitors a single blockchain for anomalies and performance metrics
func (ccm *CrossChainMonitoring) monitorChain(chain blockchain.Blockchain) {
    defer ccm.monitoringWG.Done()
    
    for {
        data, err := chain.CollectData()
        if err != nil {
            log.Printf("Error collecting data from chain %s: %v", chain.Name(), err)
            continue
        }

        encryptedData, err := encryption.EncryptData(data)
        if err != nil {
            log.Printf("Error encrypting data from chain %s: %v", chain.Name(), err)
            continue
        }

        err = ccm.processData(chain, encryptedData)
        if err != nil {
            log.Printf("Error processing data from chain %s: %v", chain.Name(), err)
            continue
        }

        time.Sleep(1 * time.Minute) // Adjust monitoring frequency as needed
    }
}

// processData processes the encrypted data collected from a blockchain
func (ccm *CrossChainMonitoring) processData(chain blockchain.Blockchain, data []byte) error {
    decryptedData, err := encryption.DecryptData(data)
    if err != nil {
        return fmt.Errorf("error decrypting data: %v", err)
    }

    metrics, err := chain.AnalyzeData(decryptedData)
    if err != nil {
        return fmt.Errorf("error analyzing data: %v", err)
    }

    if err := ccm.checkForAnomalies(metrics); err != nil {
        return fmt.Errorf("anomaly detected: %v", err)
    }

    if err := ccm.logMetrics(chain, metrics); err != nil {
        return fmt.Errorf("error logging metrics: %v", err)
    }

    return nil
}

// checkForAnomalies checks the analyzed metrics for any anomalies
func (ccm *CrossChainMonitoring) checkForAnomalies(metrics blockchain.Metrics) error {
    if metrics.Latency > 100 || metrics.ErrorRate > 0.05 {
        return fmt.Errorf("high latency or error rate detected")
    }
    return nil
}

// logMetrics logs the analyzed metrics to the blockchain for transparency and auditability
func (ccm *CrossChainMonitoring) logMetrics(chain blockchain.Blockchain, metrics blockchain.Metrics) error {
    logData, err := utils.Serialize(metrics)
    if err != nil {
        return fmt.Errorf("error serializing metrics: %v", err)
    }

    encryptedLogData, err := encryption.EncryptData(logData)
    if err != nil {
        return fmt.Errorf("error encrypting log data: %v", err)
    }

    return chain.LogData(encryptedLogData)
}

// AddChain adds a new blockchain to the cross-chain monitoring system
func (ccm *CrossChainMonitoring) AddChain(chain blockchain.Blockchain) {
    ccm.chains = append(ccm.chains, chain)
}

// RemoveChain removes a blockchain from the cross-chain monitoring system
func (ccm *CrossChainMonitoring) RemoveChain(chainName string) {
    for i, chain := range ccm.chains {
        if chain.Name() == chainName {
            ccm.chains = append(ccm.chains[:i], ccm.chains[i+1:]...)
            break
        }
    }
}
