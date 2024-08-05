package on_premise

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "os"
    "os/exec"

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
    // Define additional node types (up to 52)
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
        // Add additional node type strings
    }[nt]
}

// NodeConfig represents the configuration for a local node
type NodeConfig struct {
    Hostname        string
    IPAddress       string
    OSImage         string
    SetupScripts    []string
    NodeType        NodeType
    CPU             string
    Memory          string
    Storage         string
    FirewallRules   []string
    MonitoringTools []string
    LogConfig       string
    SSHPort         int
}

// Node represents a local node
type Node struct {
    Config     NodeConfig
    PrivateKey *rsa.PrivateKey
}

// GenerateSSHKey generates an SSH key for the node
func (n *Node) GenerateSSHKey() error {
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return err
    }
    n.PrivateKey = privateKey

    privateKeyPEM := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PRIVATE KEY",
            Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
        },
    )

    publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
    if err != nil {
        return err
    }
    n.Config.SSHKey = string(ssh.MarshalAuthorizedKey(publicKey))

    err = ioutil.WriteFile("id_rsa", privateKeyPEM, 0600)
    if err != nil {
        return err
    }

    return nil
}

// SetupNetwork configures network settings for the node
func (n *Node) SetupNetwork() error {
    commands := []string{
        fmt.Sprintf("hostnamectl set-hostname %s", n.Config.Hostname),
        fmt.Sprintf("ip addr add %s dev eth0", n.Config.IPAddress),
    }
    return n.runCommands(commands)
}

// SetupHardware configures hardware settings for the node
func (n *Node) SetupHardware() error {
    commands := []string{
        fmt.Sprintf("echo %s > /proc/sys/vm/drop_caches", n.Config.Memory),
        fmt.Sprintf("echo %s > /sys/block/sda/queue/nr_requests", n.Config.Storage),
    }
    return n.runCommands(commands)
}

// SetupSecurity configures security settings for the node
func (n *Node) SetupSecurity() error {
    commands := []string{
        fmt.Sprintf("ufw allow %d/tcp", n.Config.SSHPort),
    }
    for _, rule := range n.Config.FirewallRules {
        commands = append(commands, fmt.Sprintf("ufw allow %s", rule))
    }
    return n.runCommands(commands)
}

// SetupMonitoring sets up monitoring tools on the node
func (n *Node) SetupMonitoring() error {
    return n.runCommands(n.Config.MonitoringTools)
}

// SetupLogging configures logging settings for the node
func (n *Node) SetupLogging() error {
    command := fmt.Sprintf("echo '%s' > /etc/rsyslog.d/node.conf", n.Config.LogConfig)
    return n.runCommand(command)
}

// RunSetupScripts executes the setup scripts on the node
func (n *Node) RunSetupScripts() error {
    return n.runCommands(n.Config.SetupScripts)
}

// InitializeNode initializes the node with necessary configurations
func (n *Node) InitializeNode() error {
    if err := n.GenerateSSHKey(); err != nil {
        return err
    }
    if err := n.SetupNetwork(); err != nil {
        return err
    }
    if err := n.SetupHardware(); err != nil {
        return err
    }
    if err := n.SetupSecurity(); err != nil {
        return err
    }
    if err := n.SetupMonitoring(); err != nil {
        return err
    }
    if err := n.SetupLogging(); err != nil {
        return err
    }
    return n.RunSetupScripts()
}

// runCommands executes a list of commands on the server
func (n *Node) runCommands(commands []string) error {
    for _, cmd := range commands {
        if err := n.runCommand(cmd); err != nil {
            return err
        }
    }
    return nil
}

// runCommand executes a single command on the server
func (n *Node) runCommand(command string) error {
    cmd := exec.Command("/bin/sh", "-c", command)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    err := cmd.Run()
    if err != nil {
        return fmt.Errorf("error executing command '%s': %s", command, out.String())
    }
    fmt.Printf("Output of command '%s': %s\n", command, out.String())
    return nil
}

// EncryptData encrypts data using AES
func EncryptData(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}

// DecryptData decrypts data using AES
func DecryptData(ciphertext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateKey generates a key using Argon2
func GenerateKey(password, salt []byte) ([]byte, error) {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

