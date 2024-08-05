package verification

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// QualityAssuranceResult stores the results of a quality assurance test.
type QualityAssuranceResult struct {
	TestName   string
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Passed     bool
	Details    string
}

// QualityAssuranceTester struct to manage quality assurance testing.
type QualityAssuranceTester struct {
	mu      sync.Mutex
	results []QualityAssuranceResult
}

// NewQualityAssuranceTester initializes a new quality assurance tester.
func NewQualityAssuranceTester() *QualityAssuranceTester {
	return &QualityAssuranceTester{}
}

// RunTest runs a quality assurance test with the given name and function.
func (qat *QualityAssuranceTester) RunTest(testName string, testFunc func() (bool, string)) QualityAssuranceResult {
	startTime := time.Now()
	passed, details := testFunc()
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	result := QualityAssuranceResult{
		TestName:  testName,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Passed:    passed,
		Details:   details,
	}

	qat.mu.Lock()
	qat.results = append(qat.results, result)
	qat.mu.Unlock()

	return result
}

// GetResults returns all quality assurance test results.
func (qat *QualityAssuranceTester) GetResults() []QualityAssuranceResult {
	qat.mu.Lock()
	defer qat.mu.Unlock()

	return qat.results
}

// DisplayResults displays the quality assurance test results in a readable format.
func (qat *QualityAssuranceTester) DisplayResults() {
	results := qat.GetResults()
	for _, result := range results {
		fmt.Printf("Test Name: %s\n", result.TestName)
		fmt.Printf("Start Time: %s\n", result.StartTime)
		fmt.Printf("End Time: %s\n", result.EndTime)
		fmt.Printf("Duration: %s\n", result.Duration)
		fmt.Printf("Passed: %t\n", result.Passed)
		fmt.Printf("Details: %s\n", result.Details)
		fmt.Println("-----------------------------")
	}
}

// Example usage of the QualityAssuranceTester.
// Note: This would normally not be part of the file as per the instruction, 
// but is provided here for clarity on how the QualityAssuranceTester can be used.
/*
func main() {
	qat := NewQualityAssuranceTester()

	// Example test functions
	test1 := func() (bool, string) {
		// Simulate some quality assurance logic here
		time.Sleep(100 * time.Millisecond)
		return true, "Test passed successfully."
	}

	test2 := func() (bool, string) {
		// Simulate some quality assurance logic here
		time.Sleep(200 * time.Millisecond)
		return false, "Test failed due to an unexpected error."
	}

	result1 := qat.RunTest("Test 1", test1)
	result2 := qat.RunTest("Test 2", test2)
	qat.DisplayResults()

	log.Printf("Test Result 1: %+v\n", result1)
	log.Printf("Test Result 2: %+v\n", result2)
}
*/
