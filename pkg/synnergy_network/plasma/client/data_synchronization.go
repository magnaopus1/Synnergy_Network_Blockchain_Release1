package client

import (
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

type SynchronizationStatus struct {
    LastSyncedBlock int
    IsSyncing       bool
    mu              sync.Mutex
}

// ClientSynchronization represents the synchronization mechanism for a client
type ClientSynchronization struct {
    client       *Client
    status       SynchronizationStatus
    syncInterval time.Duration
}

// NewClientSynchronization creates a new synchronization mechanism for a client
func NewClientSynchronization(client *Client, syncInterval time.Duration) *ClientSynchronization {
    return &ClientSynchronization{
        client: client,
        status: SynchronizationStatus{
            LastSyncedBlock: 0,
            IsSyncing:       false,
        },
        syncInterval: syncInterval,
    }
}

// startSynchronization starts the synchronization process at regular intervals
func (cs *ClientSynchronization) startSynchronization() {
    ticker := time.NewTicker(cs.syncInterval)
    go func() {
        for range ticker.C {
            if err := cs.synchronizeWithNetwork(); err != nil {
                fmt.Println("Synchronization error:", err)
            }
        }
    }()
}

// synchronizeWithNetwork synchronizes the client with the blockchain network
func (cs *ClientSynchronization) synchronizeWithNetwork() error {
    cs.status.mu.Lock()
    if cs.status.IsSyncing {
        cs.status.mu.Unlock()
        return errors.New("synchronization already in progress")
    }
    cs.status.IsSyncing = true
    cs.status.mu.Unlock()

    defer func() {
        cs.status.mu.Lock()
        cs.status.IsSyncing = false
        cs.status.mu.Unlock()
    }()

    latestBlock, err := cs.fetchLatestBlockFromNetwork()
    if err != nil {
        return err
    }

    cs.status.mu.Lock()
    currentLastSyncedBlock := cs.status.LastSyncedBlock
    cs.status.mu.Unlock()

    if latestBlock.Index > currentLastSyncedBlock {
        for i := currentLastSyncedBlock + 1; i <= latestBlock.Index; i++ {
            block, err := cs.fetchBlockFromNetwork(i)
            if err != nil {
                return err
            }
            if err := cs.client.bc.AddBlock(block); err != nil {
                return err
            }
            cs.status.mu.Lock()
            cs.status.LastSyncedBlock = i
            cs.status.mu.Unlock()
        }
    }

    return nil
}

// fetchLatestBlockFromNetwork fetches the latest block from the network
func (cs *ClientSynchronization) fetchLatestBlockFromNetwork() (child_chain.Block, error) {
    response, err := http.Get("http://localhost:8080/latestBlock")
    if err != nil {
        return child_chain.Block{}, err
    }
    defer response.Body.Close()

    if response.StatusCode != http.StatusOK {
        return child_chain.Block{}, errors.New("failed to fetch latest block")
    }

    var block child_chain.Block
    if err := json.NewDecoder(response.Body).Decode(&block); err != nil {
        return child_chain.Block{}, err
    }

    return block, nil
}

// fetchBlockFromNetwork fetches a specific block from the network by index
func (cs *ClientSynchronization) fetchBlockFromNetwork(index int) (child_chain.Block, error) {
    response, err := http.Get(fmt.Sprintf("http://localhost:8080/block/%d", index))
    if err != nil {
        return child_chain.Block{}, err
    }
    defer response.Body.Close()

    if response.StatusCode != http.StatusOK {
        return child_chain.Block{}, errors.New("failed to fetch block")
    }

    var block child_chain.Block
    if err := json.NewDecoder(response.Body).Decode(&block); err != nil {
        return child_chain.Block{}, err
    }

    return block, nil
}

// AddBlock adds a block to the blockchain
func (bc *child_chain.Blockchain) AddBlock(block child_chain.Block) error {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    if len(bc.Chain) > 0 {
        lastBlock := bc.Chain[len(bc.Chain)-1]
        if block.PreviousHash != lastBlock.Hash {
            return errors.New("block's previous hash does not match the last block's hash")
        }
    }

    bc.Chain = append(bc.Chain, block)
    return nil
}
