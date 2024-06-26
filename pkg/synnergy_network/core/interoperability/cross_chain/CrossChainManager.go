package cross_chain

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// CrossChainManager coordinates all cross-chain operations and transactions.
type CrossChainManager struct {
    mu                 sync.Mutex
    assetTransferMgr   *AssetTransferManager
    contractInvokerMgr *ContractInvoker
    bridgeServiceMgr   *BridgeService
    chainLinkMgr       *ChainLinkManager
}

// NewCrossChainManager creates a new manager for handling cross-chain operations.
func NewCrossChainManager() *CrossChainManager {
    return &CrossChainManager{
        assetTransferMgr:   NewAssetTransferManager(),
        contractInvokerMgr: NewContractInvoker(),
        bridgeServiceMgr:   NewBridgeService(),
        chainLinkMgr:       NewChainLinkManager(),
    }
}

// InitiateAssetTransfer starts the process of transferring assets between blockchains.
func (cm *CrossChainManager) InitiateAssetTransfer(source, destination, assetType string, amount float64) (*AssetTransfer, error) {
    return cm.assetTransferMgr.InitiateTransfer(source, destination, assetType, amount)
}

// InvokeContractAcrossChain handles the invocation of a contract on a remote blockchain.
func (cm *CrossChainManager) InvokeContractAcrossChain(invocationDetails *ContractInvocation) error {
    if err := cm.contractInvokerMgr.InvokeContract(invocationDetails); err != nil {
        return fmt.Errorf("error invoking contract across chain: %v", err)
    }
    return nil
}

// EstablishBridge between two blockchains to facilitate cross-chain interactions.
func (cm *CrossChainManager) EstablishBridge(sourceChain, destinationChain string) error {
    return cm.bridgeServiceMgr.CreateBridge(sourceChain, destinationChain)
}

// ActivateChainLink creates a link between two chains for continuous synchronization and data sharing.
func (cm *CrossChainManager) ActivateChainLink(sourceChain, destinationChain string) error {
    return cm.chainLinkMgr.CreateLink(sourceChain, destinationChain)
}

// ListAllActivities returns a summary of all ongoing and completed cross-chain activities.
func (cm *CrossChainManager) ListAllActivities() map[string][]interface{} {
    activities := make(map[string][]interface{})
    activities["AssetTransfers"] = cm.assetTransferMgr.ListTransfers()
    activities["ContractInvocations"] = cm.contractInvokerMgr.ListInvocations()
    activities["Bridges"] = cm.bridgeServiceMgr.ListBridges()
    activities["Links"] = cm.chainLinkMgr.ListLinks()
    return activities
}

// MonitorActivity monitors and logs all cross-chain activities to ensure transparency and auditability.
func (cm *CrossChainManager) MonitorActivity() {
    fmt.Println("Monitoring all cross-chain activities...")
    for _, activity := range cm.ListAllActivities() {
        for _, detail := range activity {
            fmt.Println("Activity detail:", detail)
        }
    }
}
