package decentralized_monitoring_network

import (
    "crypto/sha256"
    "encoding/json"
    "log"
    "sync"
    "time"

    "github.com/synnergy_network/core/utils"
)

// Node represents a node in the decentralized monitoring network
type Node struct {
    ID             string
    IPAddress      string
    PublicKey      string
    Reputation     float64
    LastHeartbeat  time.Time
    MonitoringData map[string]interface{}
}

// ConsensusData represents the data required for consensus
type ConsensusData struct {
    NodeID        string
    Timestamp     time.Time
    MonitoringData map[string]interface{}
    Signature     string
}

// ConsensusMechanism handles consensus for monitoring data
type ConsensusMechanism struct {
    Nodes           map[string]*Node
    ConsensusData   map[string][]ConsensusData
    mutex           sync.Mutex
    quorumThreshold float64
}

// NewConsensusMechanism initializes a new ConsensusMechanism
func NewConsensusMechanism(quorumThreshold float64) *ConsensusMechanism {
    return &ConsensusMechanism{
        Nodes:           make(map[string]*Node),
        ConsensusData:   make(map[string][]ConsensusData),
        quorumThreshold: quorumThreshold,
    }
}

// RegisterNode registers a new node to the monitoring network
func (cm *ConsensusMechanism) RegisterNode(id, ipAddress, publicKey string) {
    cm.mutex.Lock()
    defer cm.mutex.Unlock()
    cm.Nodes[id] = &Node{
        ID:             id,
        IPAddress:      ipAddress,
        PublicKey:      publicKey,
        Reputation:     1.0,
        LastHeartbeat:  time.Now(),
        MonitoringData: make(map[string]interface{}),
    }
}

// ReceiveMonitoringData handles incoming monitoring data from nodes
func (cm *ConsensusMechanism) ReceiveMonitoringData(nodeID string, data map[string]interface{}, signature string) {
    cm.mutex.Lock()
    defer cm.mutex.Unlock()

    node, exists := cm.Nodes[nodeID]
    if !exists {
        log.Printf("Node %s not registered\n", nodeID)
        return
    }

    if !utils.VerifySignature(node.PublicKey, data, signature) {
        log.Printf("Invalid signature from node %s\n", nodeID)
        return
    }

    consensusData := ConsensusData{
        NodeID:        nodeID,
        Timestamp:     time.Now(),
        MonitoringData: data,
        Signature:     signature,
    }
    cm.ConsensusData[nodeID] = append(cm.ConsensusData[nodeID], consensusData)

    cm.checkForConsensus(nodeID)
}

// checkForConsensus checks if the consensus threshold is met for a node's data
func (cm *ConsensusMechanism) checkForConsensus(nodeID string) {
    consensusList := cm.ConsensusData[nodeID]
    if len(consensusList) == 0 {
        return
    }

    dataHash := hashMonitoringData(consensusList[0].MonitoringData)
    var agreeCount int

    for _, cd := range consensusList {
        if hashMonitoringData(cd.MonitoringData) == dataHash {
            agreeCount++
        }
    }

    if float64(agreeCount)/float64(len(cm.Nodes)) >= cm.quorumThreshold {
        log.Printf("Consensus reached for node %s with %d/%d agreeing\n", nodeID, agreeCount, len(cm.Nodes))
        cm.finalizeConsensus(nodeID, consensusList[0].MonitoringData)
    }
}

// finalizeConsensus finalizes the consensus process for a node's data
func (cm *ConsensusMechanism) finalizeConsensus(nodeID string, data map[string]interface{}) {
    // Finalize the consensus and take any necessary actions
    log.Printf("Finalizing consensus for node %s with data: %v\n", nodeID, data)
    // Additional actions like storing the data in blockchain, notifying other nodes, etc.
}

// hashMonitoringData creates a hash of the monitoring data
func hashMonitoringData(data map[string]interface{}) string {
    dataBytes, _ := json.Marshal(data)
    hash := sha256.Sum256(dataBytes)
    return string(hash[:])
}
