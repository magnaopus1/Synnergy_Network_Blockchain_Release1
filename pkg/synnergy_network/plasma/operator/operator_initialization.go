package operator

import (
    "errors"
    "log"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
    "github.com/synnergy_network_blockchain/plasma/client"
    "github.com/synnergy_network_blockchain/plasma/contract"
    "github.com/synnergy_network_blockchain/plasma/node"
)

// OperatorConfig holds the configuration for initializing an operator
type OperatorConfig struct {
    ChainManagerConfig    child_chain.ChainManagerConfig
    ClientManagerConfig   client.ClientManagerConfig
    ContractManagerConfig contract.ContractManagerConfig
    NodeManagerConfig     node.NodeManagerConfig
}

// Operator represents a blockchain operator with all the necessary managers
type Operator struct {
    ChainManager    *child_chain.ChainManager
    ClientManager   *client.ClientManager
    ContractManager *contract.ContractManager
    NodeManager     *node.NodeManager
    initialized     bool
    mu              sync.Mutex
}

// NewOperator initializes a new Operator
func NewOperator(config OperatorConfig) (*Operator, error) {
    chainManager, err := child_chain.NewChainManager(config.ChainManagerConfig)
    if err != nil {
        return nil, err
    }

    clientManager, err := client.NewClientManager(config.ClientManagerConfig)
    if err != nil {
        return nil, err
    }

    contractManager, err := contract.NewContractManager(config.ContractManagerConfig)
    if err != nil {
        return nil, err
    }

    nodeManager, err := node.NewNodeManager(config.NodeManagerConfig)
    if err != nil {
        return nil, err
    }

    return &Operator{
        ChainManager:    chainManager,
        ClientManager:   clientManager,
        ContractManager: contractManager,
        NodeManager:     nodeManager,
        initialized:     true,
    }, nil
}

// Start initializes and starts the operator's components
func (o *Operator) Start() error {
    o.mu.Lock()
    defer o.mu.Unlock()

    if !o.initialized {
        return errors.New("operator is not initialized")
    }

    log.Println("Starting Chain Manager...")
    if err := o.ChainManager.Start(); err != nil {
        return err
    }

    log.Println("Starting Client Manager...")
    if err := o.ClientManager.Start(); err != nil {
        return err
    }

    log.Println("Starting Contract Manager...")
    if err := o.ContractManager.Start(); err != nil {
        return err
    }

    log.Println("Starting Node Manager...")
    if err := o.NodeManager.Start(); err != nil {
        return err
    }

    log.Println("Operator started successfully.")
    return nil
}

// Stop stops the operator's components
func (o *Operator) Stop() error {
    o.mu.Lock()
    defer o.mu.Unlock()

    if !o.initialized {
        return errors.New("operator is not initialized")
    }

    log.Println("Stopping Chain Manager...")
    if err := o.ChainManager.Stop(); err != nil {
        return err
    }

    log.Println("Stopping Client Manager...")
    if err := o.ClientManager.Stop(); err != nil {
        return err
    }

    log.Println("Stopping Contract Manager...")
    if err := o.ContractManager.Stop(); err != nil {
        return err
    }

    log.Println("Stopping Node Manager...")
    if err := o.NodeManager.Stop(); err != nil {
        return err
    }

    log.Println("Operator stopped successfully.")
    return nil
}

// Restart restarts the operator's components
func (o *Operator) Restart() error {
    if err := o.Stop(); err != nil {
        return err
    }
    return o.Start()
}
