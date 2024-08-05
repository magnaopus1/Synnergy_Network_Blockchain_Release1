package consensus

import (
	"testing"
	"time"

	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)


func TestHybridConsensusInitialization(t *testing.T) {
	nodeID := "node123"
	hc := hybrid.NewHybridConsensus(nodeID)

	if hc.PoWWeight != 40.0 {
		t.Errorf("Expected PoWWeight to be 40.0, got %f", hc.PoWWeight)
	}
	if hc.PoSWeight != 30.0 {
		t.Errorf("Expected PoSWeight to be 30.0, got %f", hc.PoSWeight)
	}
	if hc.PoHWeight != 30.0 {
		t.Errorf("Expected PoHWeight to be 30.0, got %f", hc.PoHWeight)
	}
	if hc.nodeID != nodeID {
		t.Errorf("Expected nodeID to be %s, got %s", nodeID, hc.nodeID)
	}
}

func TestTransitionConsensus(t *testing.T) {
	hc := NewHybridConsensus("node123")

	err := hc.TransitionConsensus(100, 10.0, 5000, 10000)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if hc.PoWWeight < 7.5 || hc.PoSWeight < 7.5 || hc.PoHWeight < 7.5 {
		t.Errorf("Consensus weighting is below minimum threshold: PoW: %f, PoS: %f, PoH: %f", hc.PoWWeight, hc.PoSWeight, hc.PoHWeight)
	}
}

func TestProcessTransactions(t *testing.T) {
	hc := NewHybridConsensus("node123")

	transactions := []*transaction.Transaction{
		NewMockTransaction("tx1"),
		NewMockTransaction("tx2"),
		NewMockTransaction("tx3"),
	}

	err := hc.ProcessTransactions(transactions)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestVerifyBlock(t *testing.T) {
	hc := hybrid.NewHybridConsensus("node123")

	block := &common.Block{
		Transactions: []*common.Transaction{
			common.NewTransaction("tx1"),
			common.NewTransaction("tx2"),
		},
		Validator: "node123",
	}

	isValid := hc.VerifyBlock(common.block)
	if !isValid {
		t.Errorf("Expected block to be valid, but it was invalid")
	}
}

func TestGenerateBlock(t *testing.T) {
	hc := NewHybridConsensus("node123")

	transactions := []*common.Transaction{
		common.NewTransaction("tx1"),
		common.NewTransaction("tx2"),
	}

	block, err := hc.GenerateBlock(transactions)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if block == nil {
		t.Errorf("Expected block to be generated, but got nil")
	}
}

func TestRun(t *testing.T) {
	hc := NewHybridConsensus("node123")

	go func() {
		err := hc.Run()
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	}()

	time.Sleep(12 * time.Second) // Give it some time to run
}
