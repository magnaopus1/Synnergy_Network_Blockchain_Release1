package on_premise

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

// NodeType represents the type of node in the blockchain network
type NodeType int

const (
	AuthorityNode NodeType = iota
	BankingNode
	ComputeNode
	DataNode
	EdgeNode
	ValidatorNode
	// ... (Add other 46 node types)
)

// String returns the string representation of the NodeType
func (nt NodeType) String() string {
	return [...]string{
		"AuthorityNode",
		"BankingNode",
		"ComputeNode",
		"DataNode",
		"EdgeNode",
		"ValidatorNode",
		// ... (Add other 46 node types as strings)
	}[nt]
}

// NodeConfig represents the configuration for a bare-metal node
type NodeConfig struct {
	Hostname     string
	IPAddress    string
	SSHKey       string
	OSImage      string
	SetupScripts []string
	NodeType     NodeType
}

// Node represents a bare-metal node
type Node struct {
	Config     NodeConfig
	PrivateKey *rsa.PrivateKey
}

// GenerateSSHKey generates an SSH key for the node
func (n *Node) GenerateSSHKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}
	n.PrivateKey = privateKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to generate public key: %v", err)
	}
	n.Config.SSHKey = string(ssh.MarshalAuthorizedKey(publicKey))

	return nil
}

// RunSetupScripts executes the setup scripts on the node
func (n *Node) RunSetupScripts() error {
	for _, script := range n.Config.SetupScripts {
		cmd := exec.Command("/bin/bash", "-c", script)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute setup script %s: %v", script, err)
		}
		fmt.Printf("Output of script %s: %s\n", script, out.String())
	}
	return nil
}

// ConfigureNode configures the node with the provided settings
func (n *Node) ConfigureNode() error {
	if err := n.GenerateSSHKey(); err != nil {
		return fmt.Errorf("error generating SSH key: %v", err)
	}

	if n.Config.NodeType < 0 || int(n.Config.NodeType) >= 52 {
		return errors.New("invalid node type")
	}

	// Additional configurations can be added here
	return nil
}

// DeployNode deploys the node
func (n *Node) DeployNode() error {
	if err := n.ConfigureNode(); err != nil {
		return fmt.Errorf("error configuring node: %v", err)
	}

	if err := n.RunSetupScripts(); err != nil {
		return fmt.Errorf("error running setup scripts: %v", err)
	}

	fmt.Printf("Node %s of type %s deployed successfully\n", n.Config.Hostname, n.Config.NodeType.String())
	return nil
}

// SecureNode secures the node using Argon2 for key derivation
func (n *Node) SecureNode(password, salt string) (string, error) {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return fmt.Sprintf("%x", hash), nil
}

// MonitorNodeHealth continuously monitors the node's health
func (n *Node) MonitorNodeHealth() {
	for {
		// Placeholder for monitoring logic, e.g., checking resource usage, running health checks
		fmt.Printf("Monitoring health of node %s\n", n.Config.Hostname)
		time.Sleep(30 * time.Second)
	}
}

// BackupNodeData performs regular backups of the node's data
func (n *Node) BackupNodeData() {
	for {
		// Placeholder for backup logic, e.g., copying data to a remote server or cloud storage
		fmt.Printf("Performing backup for node %s\n", n.Config.Hostname)
		time.Sleep(24 * time.Hour)
	}
}

// RestoreNodeData restores the node's data from a backup
func (n *Node) RestoreNodeData() error {
	// Placeholder for restoration logic
	fmt.Printf("Restoring data for node %s\n", n.Config.Hostname)
	return nil
}

func main() {
	nodeConfig := NodeConfig{
		Hostname:     "node1",
		IPAddress:    "192.168.1.100",
		OSImage:      "ubuntu-20.04",
		SetupScripts: []string{"sudo apt update", "sudo apt install -y docker.io"},
		NodeType:     ValidatorNode, // Assign a valid node type here
	}

	node := Node{
		Config: nodeConfig,
	}

	if err := node.DeployNode(); err != nil {
		fmt.Printf("Error deploying node: %v\n", err)
	}

	go node.MonitorNodeHealth()
	go node.BackupNodeData()

	select {} // Keep the main function running
}
