package consensus

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

type MiningProcess struct {
    Blockchain        []*common.Block
    TransactionPool   []*common.Transaction
    BlockReward       *big.Int
    Difficulty        int
    NetworkHashrate   float64
    MiningTarget      string
    HalvingInterval   int
    BlockInterval     time.Duration
    MinerConfig       *common.MinerConfig
    PublicKeyProvider common.PublicKeyProvider
    lock              sync.Mutex
}

func NewMiningProcess() *MiningProcess {
    mc := common.DefaultMinerConfig()
    mp := &MiningProcess{
        Blockchain:        make([]*common.Block, 0),
        TransactionPool:   make([]*common.Transaction, 0),
        BlockReward:       big.NewInt(1252),
        Difficulty:        16,
        HalvingInterval:   200000,
        BlockInterval:     10 * time.Minute,
        MinerConfig:       mc,
        PublicKeyProvider: common.DefaultPublicKeyProvider,
    }
    mp.calculateMiningTarget()
    return mp
}

func (mp *MiningProcess) calculateMiningTarget() {
    target := big.NewInt(1)
    target.Lsh(target, uint(256-mp.Difficulty))
    mp.MiningTarget = target.Text(16)
}

func (mp *MiningProcess) MineBlock() (*common.Block, error) {
    mp.lock.Lock()
    defer mp.lock.Unlock()

    block := &common.Block{
        Timestamp:    time.Now().Unix(),
        Transactions: mp.TransactionPool,
        PrevBlockHash: func() string {
            if len(mp.Blockchain) > 0 {
                return mp.Blockchain[len(mp.Blockchain)-1].Hash
            }
            return ""
        }(),
    }

    mp.switchHashingAlgorithm()

    for nonce := uint64(0); ; nonce++ {
        block.Nonce = int(nonce)
        if hash, err := mp.CalculateBlockHash(block); err == nil && mp.ValidateBlockHash(hash) {
            block.Hash = hash
            break
        }
    }

    mp.TransactionPool = []*common.Transaction{}
    mp.Blockchain = append(mp.Blockchain, block)

    mp.adjustDifficulty()
    mp.adjustBlockReward()

    return block, nil
}

func (mp *MiningProcess) CalculateBlockHash(block *common.Block) (string, error) {
    data := blockData(block)
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    var hash []byte
    var err error
    switch mp.MinerConfig.Algorithm {
    case "argon2":
        hash = argon2.IDKey(data, salt, mp.MinerConfig.Iterations, mp.MinerConfig.Memory, mp.MinerConfig.Parallelism, mp.MinerConfig.KeyLength)
    case "scrypt":
        hash, err = scrypt.Key(data, salt, int(mp.MinerConfig.Iterations), int(mp.MinerConfig.Memory), int(mp.MinerConfig.Parallelism), int(mp.MinerConfig.KeyLength))
        if err != nil {
            return "", err
        }
    case "sha256":
        hasher := sha256.New()
        hasher.Write(data)
        hash = hasher.Sum(nil)
    default:
        return "", errors.New("unsupported hashing algorithm")
    }

    return hex.EncodeToString(hash), nil
}

func (mp *MiningProcess) ValidateBlockHash(hash string) bool {
    targetHash, _ := new(big.Int).SetString(mp.MiningTarget, 16)
    blockHash, _ := new(big.Int).SetString(hash, 16)
    return blockHash.Cmp(targetHash) == -1
}

func (mp *MiningProcess) adjustDifficulty() {
    if len(mp.Blockchain)%2016 == 0 && len(mp.Blockchain) > 0 {
        expectedTime := int64(mp.BlockInterval.Seconds() * 2016)
        actualTime := mp.Blockchain[len(mp.Blockchain)-1].Timestamp - mp.Blockchain[len(mp.Blockchain)-2016].Timestamp
        if actualTime < expectedTime {
            mp.Difficulty++
        } else if actualTime > expectedTime {
            mp.Difficulty--
        }
        mp.calculateMiningTarget()
    }
}

func (mp *MiningProcess) adjustBlockReward() {
    if len(mp.Blockchain)%mp.HalvingInterval == 0 && len(mp.Blockchain) > 0 {
        mp.BlockReward.Div(mp.BlockReward, big.NewInt(2))
    }
}

func (mp *MiningProcess) switchHashingAlgorithm() {
    const performanceThreshold = 1000000 // Example threshold for hashrate in H/s

    if mp.NetworkHashrate < performanceThreshold {
        mp.MinerConfig.Algorithm = "scrypt"
        fmt.Println("Switched to Scrypt due to low network hashrate.")
    } else {
        mp.MinerConfig.Algorithm = "argon2"
        fmt.Println("Using Argon2 for optimal security.")
    }
}

func (mp *MiningProcess) AddTransaction(tx *common.Transaction) error {
    mp.lock.Lock()
    defer mp.lock.Unlock()

    for _, transaction := range mp.TransactionPool {
        if transaction.Sender == tx.Sender && transaction.Amount == tx.Amount && transaction.Receiver == tx.Receiver {
            return errors.New("double spending attempt detected")
        }
    }

    if !mp.validateSignature(tx) {
        return errors.New("invalid transaction signature")
    }

    mp.TransactionPool = append(mp.TransactionPool, tx)
    fmt.Println("Transaction added successfully")
    return nil
}

func (mp *MiningProcess) validateSignature(tx *common.Transaction) bool {
    publicKey, err := mp.PublicKeyProvider.GetPublicKey(tx.Sender)
    if err != nil {
        fmt.Printf("Error getting public key: %v\n", err)
        return false
    }

    if len(tx.Signature)%2 != 0 {
        fmt.Println("Error: Signature length is not even, cannot split R and S correctly")
        return false
    }

    sigR, sigS := new(big.Int), new(big.Int)
    sigR.SetBytes(tx.Signature[:len(tx.Signature)/2])
    sigS.SetBytes(tx.Signature[len(tx.Signature)/2:])

    hasher := sha256.New()
    data := fmt.Sprintf("%s:%s:%.6f:%.6f", tx.Sender, tx.Receiver, tx.Amount, tx.Fee)
    hasher.Write([]byte(data))
    hash := hasher.Sum(nil)

    fmt.Printf("Data used for hash: %s\n", data)
    fmt.Printf("Hash: %x\n", hash)
    fmt.Printf("R: %x, S: %x\n", sigR, sigS)
    fmt.Printf("Public Key: %+v\n", publicKey)

    verified := ecdsa.Verify(publicKey, hash, sigR, sigS)
    if !verified {
        fmt.Println("Signature verification failed")
    }
    return verified
}

func blockData(block *common.Block) []byte {
    blockInfo := fmt.Sprintf("%d%s%d", block.Timestamp, block.PrevBlockHash, block.Nonce)
    return append([]byte(blockInfo), concatTransactions(block.Transactions)...)
}

func concatTransactions(transactions []*common.Transaction) string {
    var result string
    for _, tx := range transactions {
        result += hex.EncodeToString(tx.Signature)
    }
    return result
}

func isHashValid(hash string, difficulty int) bool {
    target := big.NewInt(1)
    target.Lsh(target, uint(256-difficulty))

    hexHash, _ := hex.DecodeString(hash)
    hashInt := new(big.Int).SetBytes(hexHash)

    return hashInt.Cmp(target) == -1
}

type RewardCalculator struct {
    TotalSupply *big.Int
}

func NewRewardCalculator() *RewardCalculator {
    return &RewardCalculator{
        TotalSupply: big.NewInt(common.TotalSynthronSupply),
    }
}

func (rc *RewardCalculator) CalculateReward(height int) *big.Int {
    halvings := height / common.BlockHalvingPeriod
    if halvings >= common.MaxHalvings {
        return big.NewInt(0)
    }
    reward := big.NewInt(common.InitialReward)
    for i := 0; i < halvings; i++ {
        reward.Div(reward, big.NewInt(2))
    }
    return reward
}

type BlockRewardManager struct {
    BlockHeight   int
    Reward        *big.Int
    TotalMinedSyn *big.Int
}

func NewBlockRewardManager() *BlockRewardManager {
    return &BlockRewardManager{
        BlockHeight:   0,
        Reward:        big.NewInt(common.InitialReward),
        TotalMinedSyn: big.NewInt(0),
    }
}

func (brm *BlockRewardManager) CalculateReward() *big.Int {
    if brm.BlockHeight%common.BlockHalvingPeriod == 0 && brm.BlockHeight != 0 {
        brm.Reward.Div(brm.Reward, big.NewInt(2))
    }

    prospectiveTotal := new(big.Int).Add(brm.TotalMinedSyn, brm.Reward)
    if prospectiveTotal.Cmp(big.NewInt(common.TotalSynthronSupply)) > 0 {
        brm.Reward.Sub(brm.Reward, new(big.Int).Sub(prospectiveTotal, big.NewInt(common.TotalSynthronSupply)))
        if brm.Reward.Cmp(big.NewInt(0)) < 0 {
            brm.Reward.SetInt64(0)
        }
    }

    return new(big.Int).Set(brm.Reward)
}

func (brm *BlockRewardManager) IncrementBlockHeight() {
    brm.TotalMinedSyn.Add(brm.TotalMinedSyn, brm.Reward)
    brm.BlockHeight++
}

type DifficultyManager struct {
    CurrentDifficulty *big.Int
    TargetBlockTime   time.Duration
    LastAdjustment    time.Time
}

func NewDifficultyManager(initialDifficulty *big.Int) *DifficultyManager {
    return &DifficultyManager{
        CurrentDifficulty: initialDifficulty,
        TargetBlockTime:   10 * time.Minute,
        LastAdjustment:    time.Now(),
    }
}

func (dm *DifficultyManager) CalculateNewDifficulty(actualTime, expectedTime time.Duration) {
    ratio := float64(actualTime) / float64(expectedTime)
    newDifficulty := float64(dm.CurrentDifficulty.Int64()) * ratio

    dampeningFactor := 0.25
    newDifficulty = (newDifficulty * (1 - dampeningFactor)) + (float64(dm.CurrentDifficulty.Int64()) * dampeningFactor)

    if newDifficulty < 1 {
        newDifficulty = 1
    }
    dm.CurrentDifficulty = big.NewInt(int64(newDifficulty))
    dm.LastAdjustment = time.Now()
}

func (dm *DifficultyManager) AdjustDifficulty(blocks []common.Block) {
    if len(blocks) < 2016 {
        return
    }

    actualTime := time.Duration(blocks[len(blocks)-1].Timestamp-blocks[0].Timestamp) * time.Second
    expectedTime := dm.TargetBlockTime * 2016

    dm.CalculateNewDifficulty(actualTime, expectedTime)
}

func (dm *DifficultyManager) SimulateBlockMining() {
    var blocks []common.Block
    for i := 0; i < 2016; i++ {
        block := dm.MineBlock()
        blocks = append(blocks, block)
    }
    dm.AdjustDifficulty(blocks)
}

func (dm *DifficultyManager) MineBlock() common.Block {
    nonce := 0
    for {
        hash := calculateHashWithNonce(nonce, dm.CurrentDifficulty)
        if hash[:len("0000")] == "0000" {
            break
        }
        nonce++
    }
    return common.Block{
        Timestamp: time.Now().Unix(),
        Nonce:     nonce,
    }
}

func calculateHashWithNonce(nonce int, difficulty *big.Int) string {
    data := fmt.Sprintf("%d:%s", nonce, difficulty.String())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

type BlockchainWrapper struct {
    *common.Blockchain
}

func CreateBlock(transactions []*common.Transaction, prevBlockHash string, config *common.MinerConfig) (*common.Block, error) {
    block := &common.Block{
        Timestamp:     time.Now().Unix(),
        Transactions:  transactions,
        PrevBlockHash: prevBlockHash,
    }

    hash, err := CalculateBlockHash(block, config)
    if err != nil {
        return nil, err
    }
    block.Hash = hash
    return block, nil
}

func (bc *BlockchainWrapper) AddBlock(block *common.Block, config *common.MinerConfig) error {
    if len(bc.Blocks) > 0 {
        block.PrevBlockHash = bc.Blocks[len(bc.Blocks)-1].Hash
    }

    hash, err := CalculateBlockHash(block, config)
    if err != nil {
        return err
    }
    block.Hash = hash

    if valid, err := ValidateBlock(block, bc.Difficulty, config); err != nil || !valid {
        return errors.New("invalid proof of work")
    }

    bc.Blocks = append(bc.Blocks, block)
    return nil
}

func (bc *BlockchainWrapper) MineBlock(transactions []*common.Transaction, config *common.MinerConfig) (*common.Block, error) {
    var newBlock *common.Block
    nonce := 0

    for {
        newBlock = &common.Block{
            Timestamp:     time.Now().Unix(),
            Transactions:  transactions,
            PrevBlockHash: bc.Blocks[len(bc.Blocks)-1].Hash,
            Nonce:         nonce,
        }
        hash, err := CalculateBlockHash(newBlock, config)
        if err != nil {
            return nil, err
        }
        newBlock.Hash = hash

        if valid, err := ValidateBlock(newBlock, bc.Difficulty, config); err == nil && valid {
            break
        }

        nonce++
    }

    if err := bc.AddBlock(newBlock, config); err != nil {
        return nil, err
    }

    return newBlock, nil
}

func CalculateBlockHash(block *common.Block, config *common.MinerConfig) (string, error) {
    data := block.BlockData()
    var hash []byte
    var err error

    switch config.Algorithm {
    case "sha256":
        hasher := sha256.New()
        hasher.Write(data)
        hash = hasher.Sum(nil)
    case "argon2":
        hash, err = common.Argon2(data, config)
        if err != nil {
            return "", fmt.Errorf("error using Argon2: %v", err)
        }
    case "scrypt":
        hash, err = common.Scrypt(data, config)
        if err != nil {
            return "", fmt.Errorf("error using Scrypt: %v", err)
        }
    default:
        return "", errors.New("unsupported hashing algorithm")
    }

    return hex.EncodeToString(hash), nil
}

func ValidateBlock(block *common.Block, difficulty int, config *common.MinerConfig) (bool, error) {
    target := common.CalculateTarget(difficulty)
    hashInt := new(big.Int)
    hashBytes, err := hex.DecodeString(block.Hash)
    if err != nil {
        return false, err
    }
    hashInt.SetBytes(hashBytes)

    return hashInt.Cmp(target) == -1, nil
}
