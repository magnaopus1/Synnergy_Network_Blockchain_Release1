package stresstesting

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "math/big"
    "time"
)

// FailureScenario represents a single failure scenario with relevant parameters
type FailureScenario struct {
    Name            string
    Description     string
    Duration        time.Duration
    FailureFunction func() error
}

// StressTester manages and executes different failure scenarios
type StressTester struct {
    Scenarios []FailureScenario
}

// NewStressTester initializes a new StressTester instance
func NewStressTester() *StressTester {
    return &StressTester{
        Scenarios: make([]FailureScenario, 0),
    }
}

// AddScenario adds a new failure scenario to the stress tester
func (st *StressTester) AddScenario(name, description string, duration time.Duration, failureFunc func() error) {
    scenario := FailureScenario{
        Name:            name,
        Description:     description,
        Duration:        duration,
        FailureFunction: failureFunc,
    }
    st.Scenarios = append(st.Scenarios, scenario)
}

// ExecuteScenario executes a specific failure scenario
func (st *StressTester) ExecuteScenario(index int) error {
    if index < 0 || index >= len(st.Scenarios) {
        return fmt.Errorf("invalid scenario index")
    }

    scenario := st.Scenarios[index]
    fmt.Printf("Executing scenario: %s\nDescription: %s\n", scenario.Name, scenario.Description)

    start := time.Now()
    err := scenario.FailureFunction()
    if err != nil {
        return fmt.Errorf("scenario %s failed: %v", scenario.Name, err)
    }

    elapsed := time.Since(start)
    if elapsed > scenario.Duration {
        return fmt.Errorf("scenario %s exceeded duration: %v", scenario.Name, elapsed)
    }

    fmt.Printf("Scenario %s executed successfully in %v\n", scenario.Name, elapsed)
    return nil
}

// ExecuteAllScenarios executes all registered failure scenarios
func (st *StressTester) ExecuteAllScenarios() error {
    for i := range st.Scenarios {
        err := st.ExecuteScenario(i)
        if err != nil {
            return err
        }
    }
    return nil
}

// Example failure scenarios

// NetworkPartition simulates a network partition
func NetworkPartition() error {
    fmt.Println("Simulating network partition...")
    // Simulate network partition by blocking communication between nodes
    time.Sleep(5 * time.Second)
    // After partition ends, restore communication
    fmt.Println("Network partition ended.")
    return nil
}

// HighLatency simulates high network latency
func HighLatency() error {
    fmt.Println("Simulating high network latency...")
    // Simulate high latency by adding delay to network operations
    time.Sleep(10 * time.Second)
    fmt.Println("High latency ended.")
    return nil
}

// RandomFailure simulates random failures in the network
func RandomFailure() error {
    fmt.Println("Simulating random failures...")
    // Randomly fail network operations
    randSleep := time.Duration(new(big.Int).Rand(rand.Reader, big.NewInt(5)).Int64()) * time.Second
    time.Sleep(randSleep)
    fmt.Println("Random failure ended.")
    return nil
}

// DDoSAttack simulates a Distributed Denial of Service attack
func DDoSAttack() error {
    fmt.Println("Simulating DDoS attack...")
    // Simulate DDoS by overwhelming the network with requests
    for i := 0; i < 1000; i++ {
        go func() {
            time.Sleep(100 * time.Millisecond)
        }()
    }
    time.Sleep(5 * time.Second)
    fmt.Println("DDoS attack ended.")
    return nil
}

// DataCorruption simulates data corruption in the network
func DataCorruption() error {
    fmt.Println("Simulating data corruption...")
    // Simulate data corruption by altering data packets
    corruptedData := make([]byte, 16)
    _, err := rand.Read(corruptedData)
    if err != nil {
        return fmt.Errorf("failed to generate corrupted data: %v", err)
    }
    fmt.Printf("Corrupted data: %s\n", hex.EncodeToString(corruptedData))
    time.Sleep(3 * time.Second)
    fmt.Println("Data corruption ended.")
    return nil
}

