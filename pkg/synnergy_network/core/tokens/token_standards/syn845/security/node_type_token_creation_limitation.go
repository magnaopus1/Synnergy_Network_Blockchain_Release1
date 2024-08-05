package security

import (
	"errors"
	"fmt"
)

// NodeType represents the type of a node in the network
type NodeType string

const (
	// Allowed Node Types
	GovernmentNode NodeType = "Government"
	CreditorNode   NodeType = "Creditor"
	CentralBankNode NodeType = "CentralBank"
	BankingNode    NodeType = "Banking"
)

// Node represents a node in the network
type Node struct {
	ID       string
	NodeType NodeType
}

// NodeRegistry stores information about all nodes in the network
var NodeRegistry = make(map[string]Node)

// RegisterNode registers a new node in the network
func RegisterNode(id string, nodeType NodeType) error {
	if id == "" {
		return errors.New("node ID cannot be empty")
	}
	if nodeType != GovernmentNode && nodeType != CreditorNode && nodeType != CentralBankNode && nodeType != BankingNode {
		return fmt.Errorf("node type %s is not allowed to create SYN845 tokens", nodeType)
	}
	NodeRegistry[id] = Node{ID: id, NodeType: nodeType}
	return nil
}

// ValidateNodeForTokenCreation validates if a node is allowed to create SYN845 tokens
func ValidateNodeForTokenCreation(nodeID string) error {
	node, exists := NodeRegistry[nodeID]
	if !exists {
		return errors.New("node not found in registry")
	}

	switch node.NodeType {
	case GovernmentNode, CreditorNode, CentralBankNode, BankingNode:
		return nil
	default:
		return fmt.Errorf("node type %s is not allowed to create SYN845 tokens", node.NodeType)
	}
}

// EnforceNodeTypeRestriction ensures the node is allowed to perform token creation
func EnforceNodeTypeRestriction(nodeID string) error {
	err := ValidateNodeForTokenCreation(nodeID)
	if err != nil {
		return err
	}
	return nil
}
