package on_premise

import (
    "bytes"
    "fmt"
    "os/exec"
    "strings"
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
    // Add other node types as necessary (up to 52)
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
        // Add other node type strings
    }[nt]
}

// NodeConfig represents the configuration for a server node
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

// Node represents a server node
type Node struct {
    Config NodeConfig
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

func main() {
    // Example usage of Node setup
    nodeConfig := NodeConfig{
        Hostname:        "node01",
        IPAddress:       "192.168.1.100",
        OSImage:         "/path/to/os/image",
        SetupScripts:    []string{"setup_network.sh", "install_dependencies.sh"},
        NodeType:        ValidatorNode,
        CPU:             "4",
        Memory:          "8G",
        Storage:         "100G",
        FirewallRules:   []string{"80/tcp", "443/tcp"},
        MonitoringTools: []string{"install_prometheus.sh", "install_grafana.sh"},
        LogConfig:       "*.* @logserver:514",
        SSHPort:         22,
    }

    node := &Node{
        Config: nodeConfig,
    }

    if err := node.InitializeNode(); err != nil {
        fmt.Printf("Error initializing node: %s\n", err)
    } else {
        fmt.Println("Node initialized successfully")
    }
}
