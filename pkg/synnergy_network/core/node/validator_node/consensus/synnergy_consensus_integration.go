package consensus

import (
	"log"
	"time"

	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

type ValidatorNode struct {
	NodeID             string
	StakeAmount        int
	DataReplicationType string
	RewardAddress      string
}

func (vn *ValidatorNode) Initialize(nodeID string, stakeAmount int, dataReplicationType, rewardAddress string) {
	vn.NodeID = nodeID
	vn.StakeAmount = stakeAmount
	vn.DataReplicationType = dataReplicationType
	vn.RewardAddress = rewardAddress
	vn.registerNode()
}

func (vn *ValidatorNode) registerNode() {
	log.Printf("Registering validator node: %s with stake: %d", vn.NodeID, vn.StakeAmount)
	common.RegisterValidatorNode(vn.NodeID, vn.StakeAmount)
}

func (vn *ValidatorNode) StartSynnergyConsensus() {
	log.Println("Starting Synnergy Consensus")
	for {
		select {
		case <-time.After(time.Second * 10):
			vn.participateInConsensus()
		}
	}
}

func (vn *ValidatorNode) participateInConsensus() {
	log.Println("Participating in consensus")
	common.RunSynnergyConsensus(vn.NodeID, vn.RewardAddress)
}

func (vn *ValidatorNode) PerformHealthCheck() {
	log.Println("Performing health check")
	status := common.GetNodeHealthStatus(vn.NodeID)
	if status.Healthy {
		log.Println("Node is healthy")
	} else {
		log.Printf("Node health check failed: %s", status.Message)
	}
}

func (vn *ValidatorNode) UpdateNodeConfiguration() {
	log.Println("Updating node configuration")
	common.UpdateValidatorNodeConfig(vn.NodeID, vn.StakeAmount)
}

func main() {
	node := ValidatorNode{}
	node.Initialize("unique-node-id", 1000, "full_replication", "0xYourWalletAddress")
	node.StartSynnergyConsensus()
}
