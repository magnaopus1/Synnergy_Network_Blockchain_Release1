package verification

import (
	"fmt"
	"sync"
	"time"
)

// PerformanceTestResult stores the results of a performance test.
type PerformanceTestResult struct {
	TestName         string
	StartTime        time.Time
	EndTime          time.Time
	Duration         time.Duration
	TransactionsTested int
	Errors           []error
}

// PerformanceTester struct to manage performance testing.
type PerformanceTester struct {
	mu      sync.Mutex
	results []PerformanceTestResult
}

// NewPerformanceTester initializes a new performance tester.
func NewPerformanceTester() *PerformanceTester {
	return &PerformanceTester{}
}

// RunTest runs a performance test with the given name and function.
func (pt *PerformanceTester) RunTest(testName string, transactions []func() error) PerformanceTestResult {
	startTime := time.Now()
	errors := []error{}
	var wg sync.WaitGroup

	for _, tx := range transactions {
		wg.Add(1)
		go func(txFunc func() error) {
			defer wg.Done()
			if err := txFunc(); err != nil {
				pt.mu.Lock()
				errors = append(errors, err)
				pt.mu.Unlock()
			}
		}(tx)
	}

	wg.Wait()
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	result := PerformanceTestResult{
		TestName:         testName,
		StartTime:        startTime,
		EndTime:          endTime,
		Duration:         duration,
		TransactionsTested: len(transactions),
		Errors:           errors,
	}

	pt.mu.Lock()
	pt.results = append(pt.results, result)
	pt.mu.Unlock()

	return result
}

// GetResults returns all performance test results.
func (pt *PerformanceTester) GetResults() []PerformanceTestResult {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	return pt.results
}

// DisplayResults displays the performance test results in a readable format.
func (pt *PerformanceTester) DisplayResults() {
	results := pt.GetResults()
	for _, result := range results {
		fmt.Printf("Test Name: %s\n", result.TestName)
		fmt.Printf("Start Time: %s\n", result.StartTime)
		fmt.Printf("End Time: %s\n", result.EndTime)
		fmt.Printf("Duration: %s\n", result.Duration)
		fmt.Printf("Transactions Tested: %d\n", result.TransactionsTested)
		if len(result.Errors) > 0 {
			fmt.Printf("Errors: %d\n", len(result.Errors))
			for _, err := range result.Errors {
				fmt.Printf("Error: %s\n", err)
			}
		} else {
			fmt.Println("Errors: None")
		}
		fmt.Println("-----------------------------")
	}
}

// Example usage of the PerformanceTester.
// Note: This would normally not be part of the file as per the instruction, 
// but is provided here for clarity on how the PerformanceTester can be used.
/*
func main() {
	pt := NewPerformanceTester()

	// Example transaction functions
	tx1 := func() error {
		time.Sleep(100 * time.Millisecond)
		return nil
	}

	tx2 := func() error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	tx3 := func() error {
		time.Sleep(300 * time.Millisecond)
		return fmt.Errorf("example error")
	}

	transactions := []func() error{tx1, tx2, tx3}
	result := pt.RunTest("Example Test", transactions)
	pt.DisplayResults()

	fmt.Printf("Test Result: %+v\n", result)
}
*/
