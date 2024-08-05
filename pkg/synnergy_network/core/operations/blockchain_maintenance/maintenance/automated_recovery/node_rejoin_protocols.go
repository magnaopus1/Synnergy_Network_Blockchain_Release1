package automated_recovery

import (
    "crypto/sha256"
    "encoding/hex"
    "log"
    "time"
    "errors"
    "math/rand"
    "sync"
    "github.com/synnergy_network/utils"
    "github.com/synnergy_network/core/operations/blockchain"
    "github.com/synnergy_network/core/operations/blockchain_consensus"
)

// NodeRejoinProtocols struct to hold node information and status
type NodeRejoinProtocols struct {
    nodeID          string
    rejoinAttempts  int
    lastRejoinTime  time.Time
    rejoinMutex     sync.Mutex
}

// NewNodeRejoinProtocols creates a new instance of NodeRejoinProtocols
func NewNodeRejoinProtocols(nodeID string) *NodeRejoinProtocols {
    return &NodeRejoinProtocols{
        nodeID:         nodeID,
        rejoinAttempts: 0,
        lastRejoinTime: time.Time{},
    }
}

// ValidateNodeIntegrity validates the integrity of the node before rejoining
func (nrp *NodeRejoinProtocols) ValidateNodeIntegrity(nodeData string) error {
    hash := sha256.New()
    hash.Write([]byte(nodeData))
    calculatedHash := hex.EncodeToString(hash.Sum(nil))

    if !blockchain.IsValidNodeDataHash(nrp.nodeID, calculatedHash) {
        return errors.New("node data integrity validation failed")
    }
    return nil
}

// RejoinNetwork attempts to rejoin the node to the network
func (nrp *NodeRejoinProtocols) RejoinNetwork() error {
    nrp.rejoinMutex.Lock()
    defer nrp.rejoinMutex.Unlock()

    // Check if the node is eligible to rejoin
    if !blockchain_consensus.IsNodeEligibleForRejoin(nrp.nodeID) {
        return errors.New("node is not eligible to rejoin the network at this time")
    }

    nrp.lastRejoinTime = time.Now()
    nrp.rejoinAttempts++

    // Simulate rejoining process with a random delay
    delay := time.Duration(rand.Intn(10)) * time.Second
    time.Sleep(delay)

    log.Printf("Node %s is attempting to rejoin the network, attempt #%d", nrp.nodeID, nrp.rejoinAttempts)

    // Validate node integrity before rejoining
    if err := nrp.ValidateNodeIntegrity(blockchain.GetNodeData(nrp.nodeID)); err != nil {
        return err
    }

    // Update the node status in the network
    if err := blockchain.UpdateNodeStatus(nrp.nodeID, "active"); err != nil {
        return err
    }

    log.Printf("Node %s has successfully rejoined the network", nrp.nodeID)
    return nil
}

// MonitorRejoinStatus continuously monitors the rejoining status of the node
func (nrp *NodeRejoinProtocols) MonitorRejoinStatus() {
    for {
        status, err := blockchain.GetNodeStatus(nrp.nodeID)
        if err != nil {
            log.Printf("Error fetching node status for %s: %v", nrp.nodeID, err)
            continue
        }

        if status == "active" {
            log.Printf("Node %s is active in the network", nrp.nodeID)
            break
        } else {
            log.Printf("Node %s is not active, retrying rejoin process", nrp.nodeID)
            if err := nrp.RejoinNetwork(); err != nil {
                log.Printf("Rejoin attempt failed for node %s: %v", nrp.nodeID, err)
            }
        }

        // Sleep for a predefined interval before checking status again
        time.Sleep(30 * time.Second)
    }
}

// StartRejoinProcess initiates the rejoining process for the node
func (nrp *NodeRejoinProtocols) StartRejoinProcess() {
    go nrp.MonitorRejoinStatus()
}

// Utility functions for encryption, decryption, and other security measures
func EncryptNodeData(data string) (string, error) {
    encryptedData, err := utils.EncryptAES(data)
    if err != nil {
        return "", err
    }
    return encryptedData, nil
}

func DecryptNodeData(encryptedData string) (string, error) {
    decryptedData, err := utils.DecryptAES(encryptedData)
    if err != nil {
        return "", err
    }
    return decryptedData, nil
}

// This function ensures that node data is securely transmitted and validated
func SecureNodeDataTransmission(nodeData string) error {
    encryptedData, err := EncryptNodeData(nodeData)
    if err != nil {
        return err
    }

    decryptedData, err := DecryptNodeData(encryptedData)
    if err != nil {
        return err
    }

    if nodeData != decryptedData {
        return errors.New("data validation failed after encryption and decryption")
    }

    return nil
}

