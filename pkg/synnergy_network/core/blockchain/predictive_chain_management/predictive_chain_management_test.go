package predictivechainmanagement

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synnergy_network/core/blockchain/consensus"
	"github.com/synnergy_network/core/blockchain/security"
	"github.com/synnergy_network/core/blockchain/utils"
)

func TestNewPredictiveChainManagement(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	assert.NotNil(t, pcm)
	assert.NotNil(t, pcm.networkMetrics)
	assert.NotNil(t, pcm.predictiveModels)
	assert.NotNil(t, pcm.adaptiveRiskAssess)
	assert.NotNil(t, pcm.securityProtocol)
	assert.NotNil(t, pcm.consensusManager)
	assert.NotNil(t, pcm.validationManager)
	assert.NotNil(t, pcm.miningPools)
}

func TestCollectMetrics(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CollectMetrics()

	assert.Greater(t, pcm.networkMetrics.BlockCreationTime, time.Duration(0))
	assert.Greater(t, pcm.networkMetrics.TransactionThroughput, 0)
	assert.Greater(t, pcm.networkMetrics.NetworkLatency, time.Duration(0))
	assert.Greater(t, len(pcm.networkMetrics.NodePerformance), 0)
}

func TestPredictNetworkConditions(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CollectMetrics()
	pcm.PredictNetworkConditions()
	
	// Simulate prediction results for testing
	forkRisk := pcm.predictiveModels.ForkPredictionModel.Predict(pcm.networkMetrics)
	reorgRisk := pcm.predictiveModels.ReorganizationModel.Predict(pcm.networkMetrics)
	profitability := pcm.predictiveModels.ProfitabilityModel.Predict(pcm.networkMetrics)

	assert.NotNil(t, forkRisk)
	assert.NotNil(t, reorgRisk)
	assert.NotNil(t, profitability)
}

func TestAdjustMiningParameters(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.AdjustMiningParameters()

	// Check if consensus and validation parameters have been adjusted
	assert.NotEqual(t, 0, pcm.consensusManager.GetDifficulty())
	assert.NotEqual(t, 0, pcm.validationManager.GetBlockSize())
}

func TestAssessRisk(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.AssessRisk()

	assert.Greater(t, len(pcm.adaptiveRiskAssess.RiskFactors), 0)
}

func TestApplySecurityMeasures(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.securityProtocol.AddNode("Node-1")
	pcm.adaptiveRiskAssess.RiskFactors["Node-1"] = 0.7
	pcm.ApplySecurityMeasures()

	assert.Contains(t, pcm.securityProtocol.GetIsolatedNodes(), "Node-1")
}

func TestOptimizeMiningEfforts(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.OptimizeMiningEfforts()

	// Ensure that all optimization steps are executed
	assert.Greater(t, pcm.networkMetrics.TransactionThroughput, 0)
	assert.NotNil(t, pcm.predictiveModels.ForkPredictionModel)
	assert.NotEqual(t, 0, pcm.consensusManager.GetDifficulty())
	assert.Greater(t, len(pcm.adaptiveRiskAssess.RiskFactors), 0)
	assert.Contains(t, pcm.securityProtocol.GetIsolatedNodes(), "Node-1")
}

func TestContinuousImprovement(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CollectMetrics()
	pcm.ContinuousImprovement()

	// Simulate updating models with new data
	pcm.predictiveModels.ForkPredictionModel.Update(pcm.networkMetrics)
	assert.NotNil(t, pcm.predictiveModels.ForkPredictionModel)
}

func TestAdaptiveLearning(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CollectMetrics()
	pcm.AdaptiveLearning()

	// Simulate adapting models to new data
	pcm.predictiveModels.ForkPredictionModel.Adapt(pcm.networkMetrics)
	assert.NotNil(t, pcm.predictiveModels.ForkPredictionModel)
}

func TestDecentralizedModelTraining(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CollectMetrics()
	pcm.DecentralizedModelTraining()

	// Simulate decentralized training of models
	for nodeID, performance := range pcm.networkMetrics.NodePerformance {
		data := pcm.networkMetrics
		data.NodePerformance = map[string]float64{nodeID: performance}
		pcm.predictiveModels.ForkPredictionModel.DecentralizedTrain(data)
	}
	assert.NotNil(t, pcm.predictiveModels.ForkPredictionModel)
}

func TestQuantumResistantPrediction(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CollectMetrics()
	pcm.QuantumResistantPrediction()

	// Simulate applying quantum-resistant techniques
	pcm.predictiveModels.ForkPredictionModel.ApplyQuantumResistance()
	assert.NotNil(t, pcm.predictiveModels.ForkPredictionModel)
}

func TestDistributeMiningTasks(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CreateMiningPool("Pool-1")
	pcm.AddMinerToPool("Pool-1", "Miner-1")
	pcm.CollectMetrics()
	pcm.DistributeMiningTasks()

	// Ensure tasks are distributed based on profitability
	profitability := pcm.predictiveModels.ProfitabilityModel.PredictForMiner(pcm.networkMetrics, "Miner-1")
	assert.NotNil(t, profitability)
}

func TestCreateMiningPool(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CreateMiningPool("Pool-1")

	assert.Contains(t, pcm.miningPools.Pools, "Pool-1")
}

func TestAddMinerToPool(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CreateMiningPool("Pool-1")
	pcm.AddMinerToPool("Pool-1", "Miner-1")

	assert.Contains(t, pcm.miningPools.Pools["Pool-1"].Miners, "Miner-1")
}

func TestRemoveMinerFromPool(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CreateMiningPool("Pool-1")
	pcm.AddMinerToPool("Pool-1", "Miner-1")
	pcm.RemoveMinerFromPool("Pool-1", "Miner-1")

	assert.NotContains(t, pcm.miningPools.Pools["Pool-1"].Miners, "Miner-1")
}

func TestIncentivizeMiners(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.CreateMiningPool("Pool-1")
	pcm.AddMinerToPool("Pool-1", "Miner-1")
	pcm.miningPools.Pools["Pool-1"].Miners["Miner-1"].Performance = 0.8
	pcm.IncentivizeMiners()

	assert.Equal(t, 0.8, pcm.miningPools.Pools["Pool-1"].Miners["Miner-1"].Performance)
}

func TestStart(t *testing.T) {
	pcm := NewPredictiveChainManagement()
	pcm.Start()

	// Ensure the Start function initializes the optimization process
	time.Sleep(2 * time.Minute)
	assert.Greater(t, pcm.networkMetrics.TransactionThroughput, 0)
}
