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
	"github.com/ethereum/go-ethereum/crypto"
)

type AllocationStrategy interface {
	AllocateFunds(amount *big.Int) (*big.Int, *big.Int, error)
}

type DynamicAllocation struct {
	LiquidityPools map[string]LiquidityData
	Client         *rpc.Client
	Auth           *bind.TransactOpts
	ContractAddress common.Address
	PrivateKey     string
	mu             sync.Mutex
	Strategy       AllocationStrategy
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

func NewDynamicAllocation(contractAddress, privateKey string, client *rpc.Client, strategy AllocationStrategy) (*DynamicAllocation, error) {
	auth, err := bind.NewTransactorWithChainID(strings.NewReader(privateKey), nil)
	if err != nil {
		return nil, err
	}

	return &DynamicAllocation{
		LiquidityPools: make(map[string]LiquidityData),
		Client:         client,
		Auth:           auth,
		ContractAddress: common.HexToAddress(contractAddress),
		PrivateKey:      privateKey,
		Strategy:        strategy,
	}, nil
}

func (da *DynamicAllocation) AddLiquidityPool(poolID string, tokenA, tokenB common.Address) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	if _, exists := da.LiquidityPools[poolID]; exists {
		return errors.New("liquidity pool already exists")
	}

	da.LiquidityPools[poolID] = LiquidityData{
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

func (da *DynamicAllocation) UpdateLiquidityData(poolID string, reserveA, reserveB, totalLiquidity *big.Int) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	if pool, exists := da.LiquidityPools[poolID]; exists {
		pool.ReserveA = reserveA
		pool.ReserveB = reserveB
		pool.TotalLiquidity = totalLiquidity
		pool.Timestamp = time.Now()
		da.LiquidityPools[poolID] = pool
		return nil
	}

	return errors.New("liquidity pool not found")
}

func (da *DynamicAllocation) GetLiquidityData(poolID string) (LiquidityData, error) {
	da.mu.Lock()
	defer da.mu.Unlock()

	if pool, exists := da.LiquidityPools[poolID]; exists {
		return pool, nil
	}

	return LiquidityData{}, errors.New("liquidity pool not found")
}

func (da *DynamicAllocation) AllocateFunds(poolID string, amount *big.Int) (*big.Int, *big.Int, error) {
	da.mu.Lock()
	defer da.mu.Unlock()

	if pool, exists := da.LiquidityPools[poolID]; exists {
		allocatedA, allocatedB, err := da.Strategy.AllocateFunds(amount)
		if err != nil {
			return nil, nil, err
		}
		pool.ReserveA.Add(pool.ReserveA, allocatedA)
		pool.ReserveB.Add(pool.ReserveB, allocatedB)
		pool.TotalLiquidity.Add(pool.TotalLiquidity, amount)
		pool.Timestamp = time.Now()
		da.LiquidityPools[poolID] = pool
		return allocatedA, allocatedB, nil
	}

	return nil, nil, errors.New("liquidity pool not found")
}

func (da *DynamicAllocation) SaveLiquidityDataToFile(filename string) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	data, err := json.MarshalIndent(da.LiquidityPools, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func (da *DynamicAllocation) LoadLiquidityDataFromFile(filename string) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var liquidityPools map[string]LiquidityData
	if err := json.Unmarshal(data, &liquidityPools); err != nil {
		return err
	}

	da.LiquidityPools = liquidityPools
	return nil
}

func (da *DynamicAllocation) MonitorLiquidityPools(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			da.mu.Lock()
			for poolID, pool := range da.LiquidityPools {
				newReserveA, newReserveB, newTotalLiquidity := fetchLatestReservesFromBlockchain(pool.TokenA, pool.TokenB)
				da.UpdateLiquidityData(poolID, newReserveA, newReserveB, newTotalLiquidity)
				fmt.Printf("Updated liquidity data for pool %s\n", poolID)
			}
			da.mu.Unlock()
		}
	}
}

func fetchLatestReservesFromBlockchain(tokenA, tokenB common.Address) (*big.Int, *big.Int, *big.Int) {
	// Simulate fetching data from the blockchain
	return big.NewInt(1000), big.NewInt(2000), big.NewInt(3000)
}
