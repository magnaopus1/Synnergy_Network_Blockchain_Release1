package orphan_node_test

import (
    "testing"
    "time"
    "github.com/stretchr/testify/assert"
    "github.com/synthron_blockchain/blockchain"
    "github.com/synthron_blockchain/orphan_node"
    "github.com/synthron_blockchain/crypto"
)

func TestNewOrphanNode(t *testing.T) {
    id := "orphan-node-001"
    address := "0.0.0.0:8080"
    privateKey := []byte("test_private_key")
    publicKey := []byte("test_public_key")

    node, err := orphan_node.NewOrphanNode(id, address, privateKey, publicKey)
    assert.NoError(t, err)
    assert.NotNil(t, node)
    assert.Equal(t, id, node.ID)
    assert.Equal(t, address, node.Address)
}

func TestStartStopOrphanNode(t *testing.T) {
    id := "orphan-node-001"
    address := "0.0.0.0:8080"
    privateKey := []byte("test_private_key")
    publicKey := []byte("test_public_key")

    node, err := orphan_node.NewOrphanNode(id, address, privateKey, publicKey)
    assert.NoError(t, err)
    assert.NotNil(t, node)

    go func() {
        err = node.Start()
        assert.NoError(t, err)
    }()

    time.Sleep(2 * time.Second)
    node.Stop()
}

func TestHandleOrphanBlock(t *testing.T) {
    id := "orphan-node-001"
    address := "0.0.0.0:8080"
    privateKey := []byte("test_private_key")
    publicKey := []byte("test_public_key")

    node, err := orphan_node.NewOrphanNode(id, address, privateKey, publicKey)
    assert.NoError(t, err)
    assert.NotNil(t, node)

    block := &blockchain.Block{
        ID:     "block-123",
        Data:   []byte("Sample block data"),
        Nonce:  123456,
        PrevID: "prev-block-123",
    }

    orphanBlock := &orphan_node.OrphanBlock{
        Block:     block,
        Timestamp: time.Now(),
        Reason:    "Network discrepancy",
    }

    node.HandleOrphanBlock(orphanBlock)
    node.Mu.Lock()
    defer node.Mu.Unlock()
    assert.Contains(t, node.Connections, block.ID)
}

func TestEncryptDecryptData(t *testing.T) {
    id := "orphan-node-001"
    address := "0.0.0.0:8080"
    privateKey := []byte("test_private_key")
    publicKey := []byte("test_public_key")

    node, err := orphan_node.NewOrphanNode(id, address, privateKey, publicKey)
    assert.NoError(t, err)
    assert.NotNil(t, node)

    data := []byte("Sample data to encrypt")
    encryptedData, err := node.EncryptData(data)
    assert.NoError(t, err)
    assert.NotNil(t, encryptedData)

    decryptedData, err := node.DecryptData(encryptedData)
    assert.NoError(t, err)
    assert.Equal(t, data, decryptedData)
}

func TestPerformSecurityAudit(t *testing.T) {
    id := "orphan-node-001"
    address := "0.0.0.0:8080"
    privateKey := []byte("test_private_key")
    publicKey := []byte("test_public_key")

    node, err := orphan_node.NewOrphanNode(id, address, privateKey, publicKey)
    assert.NoError(t, err)
    assert.NotNil(t, node)

    err = node.PerformSecurityAudit()
    assert.NoError(t, err)
}

func TestArchiveRetrieveBlock(t *testing.T) {
    id := "orphan-node-001"
    address := "0.0.0.0:8080"
    privateKey := []byte("test_private_key")
    publicKey := []byte("test_public_key")

    node, err := orphan_node.NewOrphanNode(id, address, privateKey, publicKey)
    assert.NoError(t, err)
    assert.NotNil(t, node)

    block := &blockchain.Block{
        ID:     "block-123",
        Data:   []byte("Sample block data"),
        Nonce:  123456,
        PrevID: "prev-block-123",
    }

    orphanBlock := &orphan_node.OrphanBlock{
        Block:     block,
        Timestamp: time.Now(),
        Reason:    "Network discrepancy",
    }

    node.ArchiveBlock(orphanBlock)
    retrievedBlock, err := node.RetrieveArchivedBlock(block.ID)
    assert.NoError(t, err)
    assert.Equal(t, orphanBlock, retrievedBlock)
}
