package liquidity_management

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

type RebalancingStrategy interface {
	Rebalance(pool LiquidityData) (*big.Int, *big.Int, error)
}

type RebalancingManager struct {
	LiquidityPools map[string]LiquidityData
	Client         *rpc.Client
	Auth           *bind.TransactOpts
	ContractAddress common.Address
	mu             sync.Mutex
	Strategy       RebalancingStrategy
}

type LiquidityData struct {
	PoolID        string
	TokenA        common.Address
	TokenB        common.Address
	ReserveA      *big.Int
	ReserveB      *big.Int
	TotalLiquidity *big.Int
	Timestamp     time.Time
}

func NewRebalancingManager(contractAddress, privateKey string, client *rpc.Client, strategy RebalancingStrategy) (*RebalancingManager, error) {
	auth, err := bind.NewTransactorWithChainID(strings.NewReader(privateKey), nil)
	if err != nil {
		return nil, err
	}

	return &RebalancingManager{
		LiquidityPools: make(map[string]LiquidityData),
		Client:         client,
		Auth:           auth,
		ContractAddress: common.HexToAddress(contractAddress),
		Strategy:        strategy,
	}, nil
}

func (rm *RebalancingManager) AddLiquidityPool(poolID string, tokenA, tokenB common.Address) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.LiquidityPools[poolID]; exists {
		return errors.New("liquidity pool already exists")
	}

	rm.LiquidityPools[poolID] = LiquidityData{
		PoolID:    poolID,
		TokenA:    tokenA,
		TokenB:    tokenB,
		ReserveA:  big.NewInt(0),
		ReserveB:  big.NewInt(0),
		TotalLiquidity: big.NewInt(0),
		Timestamp: time.Now(),
	}

	return nil
}

func (rm *RebalancingManager) UpdateLiquidityData(poolID string, reserveA, reserveB, totalLiquidity *big.Int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if pool, exists := rm.LiquidityPools[poolID]; exists {
		pool.ReserveA = reserveA
		pool.ReserveB = reserveB
		pool.TotalLiquidity = totalLiquidity
		pool.Timestamp = time.Now()
		rm.LiquidityPools[poolID] = pool
		return nil
	}

	return errors.New("liquidity pool not found")
}

func (rm *RebalancingManager) GetLiquidityData(poolID string) (LiquidityData, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if pool, exists := rm.LiquidityPools[poolID]; exists {
		return pool, nil
	}

	return LiquidityData{}, errors.New("liquidity pool not found")
}

func (rm *RebalancingManager) Rebalance(poolID string) (*big.Int, *big.Int, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if pool, exists := rm.LiquidityPools[poolID]; exists {
		allocatedA, allocatedB, err := rm.Strategy.Rebalance(pool)
		if err != nil {
			return nil, nil, err
		}
		pool.ReserveA.Add(pool.ReserveA, allocatedA)
		pool.ReserveB.Add(pool.ReserveB, allocatedB)
		pool.TotalLiquidity.Add(pool.TotalLiquidity, new(big.Int).Add(allocatedA, allocatedB))
		pool.Timestamp = time.Now()
		rm.LiquidityPools[poolID] = pool
		return allocatedA, allocatedB, nil
	}

	return nil, nil, errors.New("liquidity pool not found")
}

func (rm *RebalancingManager) SaveLiquidityDataToFile(filename string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := json.MarshalIndent(rm.LiquidityPools, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func (rm *RebalancingManager) LoadLiquidityDataFromFile(filename string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var liquidityPools map[string]LiquidityData
	if err := json.Unmarshal(data, &liquidityPools); err != nil {
		return err
	}

	rm.LiquidityPools = liquidityPools
	return nil
}

func (rm *RebalancingManager) MonitorLiquidityPools(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.mu.Lock()
			for poolID, pool := range rm.LiquidityPools {
				newReserveA, newReserveB, newTotalLiquidity := fetchLatestReservesFromBlockchain(pool.TokenA, pool.TokenB)
				rm.UpdateLiquidityData(poolID, newReserveA, newReserveB, newTotalLiquidity)
				fmt.Printf("Updated liquidity data for pool %s\n", poolID)
			}
			rm.mu.Unlock()
		}
	}
}

func fetchLatestReservesFromBlockchain(tokenA, tokenB common.Address) (*big.Int, *big.Int, *big.Int) {
	// Simulate fetching data from the blockchain
	return big.NewInt(1000), big.NewInt(2000), big.NewInt(3000)
}
