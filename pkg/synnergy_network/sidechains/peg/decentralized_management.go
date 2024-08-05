package peg

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/util"
)

// DecentralizedManagement manages the decentralized aspects of the blockchain.
type DecentralizedManagement struct {
	nodes         map[string]*Node
	mutex         sync.Mutex
	logger        *log.Logger
	consensusAlgo ConsensusAlgorithm
}

// Node represents a node in the decentralized network.
type Node struct {
	ID        string
	Endpoint  string
	PublicKey string
	Status    string
	LastPing  time.Time
}

// ConsensusAlgorithm represents the consensus algorithm used.
type ConsensusAlgorithm interface {
	ProposeBlock(nodeID string, blockData []byte) error
	VoteOnBlock(nodeID string, blockHash []byte) error
}

// NewDecentralizedManagement creates a new instance of DecentralizedManagement.
func NewDecentralizedManagement(logger *log.Logger, consensusAlgo ConsensusAlgorithm) *DecentralizedManagement {
	return &DecentralizedManagement{
		nodes:         make(map[string]*Node),
		logger:        logger,
		consensusAlgo: consensusAlgo,
	}
}

// AddNode adds a new node to the network.
func (dm *DecentralizedManagement) AddNode(nodeID, endpoint, publicKey string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if _, exists := dm.nodes[nodeID]; exists {
		return errors.New("node already exists")
	}

	node := &Node{
		ID:        nodeID,
		Endpoint:  endpoint,
		PublicKey: publicKey,
		Status:    "active",
		LastPing:  time.Now(),
	}

	dm.nodes[nodeID] = node
	dm.logger.Println("New node added:", nodeID)
	return nil
}

// RemoveNode removes a node from the network.
func (dm *DecentralizedManagement) RemoveNode(nodeID string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if _, exists := dm.nodes[nodeID]; !exists {
		return errors.New("node not found")
	}

	delete(dm.nodes, nodeID)
	dm.logger.Println("Node removed:", nodeID)
	return nil
}

// GetNodeStatus gets the status of a node.
func (dm *DecentralizedManagement) GetNodeStatus(nodeID string) (string, error) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return "", errors.New("node not found")
	}

	return node.Status, nil
}

// UpdateNodeStatus updates the status of a node.
func (dm *DecentralizedManagement) UpdateNodeStatus(nodeID, status string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	node.Status = status
	node.LastPing = time.Now()
	dm.logger.Println("Node status updated:", nodeID, "Status:", status)
	return nil
}

// ProposeBlock proposes a new block to the network.
func (dm *DecentralizedManagement) ProposeBlock(nodeID string, blockData []byte) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	encryptedBlockData, err := crypto.EncryptAES(node.PublicKey, blockData)
	if err != nil {
		return err
	}

	err = dm.consensusAlgo.ProposeBlock(nodeID, encryptedBlockData)
	if err != nil {
		return err
	}

	dm.logger.Println("Block proposed by node:", nodeID)
	return nil
}

// VoteOnBlock allows a node to vote on a proposed block.
func (dm *DecentralizedManagement) VoteOnBlock(nodeID string, blockHash []byte) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	err := dm.consensusAlgo.VoteOnBlock(nodeID, blockHash)
	if err != nil {
		return err
	}

	dm.logger.Println("Block voted on by node:", nodeID)
	return nil
}

// BroadcastMessage broadcasts a message to all nodes in the network.
func (dm *DecentralizedManagement) BroadcastMessage(message []byte) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	for _, node := range dm.nodes {
		err := util.SendMessage(node.Endpoint, message)
		if err != nil {
			dm.logger.Println("Failed to send message to node:", node.ID, err)
			continue
		}
		dm.logger.Println("Message sent to node:", node.ID)
	}

	return nil
}

// HandleNodePing handles a ping from a node to keep it active.
func (dm *DecentralizedManagement) HandleNodePing(nodeID string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	node.LastPing = time.Now()
	dm.logger.Println("Node ping received:", nodeID)
	return nil
}
