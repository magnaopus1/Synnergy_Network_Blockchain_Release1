package cross_chain

import (
    "errors"
    "fmt"
    "sync"
)

// ContractInvocation represents an invocation request for a smart contract on another blockchain.
type ContractInvocation struct {
    ID              string
    SourceChain     string
    DestinationChain string
    ContractAddress string
    Method          string
    Parameters      []interface{}
    Response        interface{}
    Error           error
}

// ContractInvoker manages the invocation of contracts across blockchains.
type ContractInvoker struct {
    mu        sync.Mutex
    invocations map[string]*ContractInvocation
    blockchainAPI BlockchainAPI // Interface to interact with blockchain nodes for contract invocation
}

// BlockchainAPI defines the interface required for interacting with blockchain nodes, particularly for contract execution.
type BlockchainAPI interface {
    InvokeContract(invocation *ContractInvocation) error
}

// NewContractInvoker creates a new contract invoker.
func NewContractInvoker(api BlockchainAPI) *ContractInvoker {
    return &ContractInvoker{
        invocations:   make(map[string]*ContractInvocation),
        blockchainAPI: api,
    }
}

// InvokeContract initiates the invocation of a smart contract on another blockchain.
func (ci *ContractInvoker) InvokeContract(invocation *ContractInvocation) error {
    ci.mu.Lock()
    defer ci.mu.Unlock()

    if _, exists := ci.invocations[invocation.ID]; exists {
        return fmt.Errorf("contract invocation already exists: %s", invocation.ID)
    }

    // Execute the contract invocation through the blockchain API.
    err := ci.blockchainAPI.InvokeContract(invocation)
    if err != nil {
        invocation.Error = err
        return err
    }

    // Store the invocation for reference and further actions.
    ci.invocations[invocation.ID] = invocation
    return nil
}

// GetInvocationResult retrieves the results of a contract invocation.
func (ci *ContractInvoker) GetInvocationResult(invocationID string) (*ContractInvocation, error) {
    ci.mu.Lock()
    defer ci.mu.Unlock()

    invocation, exists := ci.invocations[invocationID]
    if !exists {
        return nil, errors.New("contract invocation does not exist")
    }

    return invocation, nil
}

// ListInvocations lists all registered contract invocations.
func (ci *ContractInvoker) ListInvocations() []*ContractInvocation {
    ci.mu.Lock()
    defer ci.mu.Unlock()

    var invocations []*ContractInvocation
    for _, invocation := range ci.invocations {
        invocations = append(invocations, invocation)
    }
    return invocations
}
