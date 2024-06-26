package cross_chain

import (
    "fmt"
    "sync"
    "time"
    "errors"
)

// TestCase represents a single test case for cross-chain functionality.
type TestCase struct {
    ID            string
    Description   string
    TestFunction  func() error
    ExpectedResult interface{}
}

// TestResult holds the outcome of a test case.
type TestResult struct {
    TestCaseID     string
    Passed         bool
    ActualResult   interface{}
    ErrorMessage   string
}

// TestingFramework manages the execution and reporting of test cases.
type TestingFramework struct {
    mu         sync.Mutex
    testCases  []*TestCase
    testResults []*TestResult
}

// NewTestingFramework creates a new testing framework.
func NewTestingFramework() *TestingFramework {
    return &TestingFramework{
        testCases:  make([]*TestCase, 0),
        testResults: make([]*TestResult, 0),
    }
}

// RegisterTestCase adds a new test case to the framework.
func (tf *TestingFramework) RegisterTestCase(testCase *TestCase) {
    tf.mu.Lock()
    defer tf.mu.Unlock()
    tf.testCases = append(tf.testCases, testCase)
    fmt.Printf("Test case registered: %s\n", testCase.Description)
}

// RunTests executes all registered test cases.
func (tf *TestingFramework) RunTests() {
    tf.mu.Lock()
    defer tf.mu.Unlock()

    for _, testCase := range tf.testCases {
        fmt.Printf("Running test case: %s\n", testCase.Description)
        err := testCase.TestFunction()
        testResult := &TestResult{
            TestCaseID: testCase.ID,
            Passed:     err == nil,
        }

        if err != nil {
            testResult.ErrorMessage = err.Error()
            testResult.ActualResult = nil
        } else {
            testResult.ActualResult = testCase.ExpectedResult
        }

        tf.testResults = append(tf.testResults, testResult)
        fmt.Printf("Test result for %s: %v\n", testCase.Description, testResult.Passed)
    }
}

// ListTestResults returns all the results from the latest test run.
func (tf *TestingFramework) ListTestResults() []*TestResult {
    tf.mu.Lock()
    defer tf.mu.Unlock()
    return tf.testResults
}

// GetTestResult provides the result for a specific test case by ID.
func (tf *TestingFramework) GetTestResult(testCaseID string) (*TestResult, error) {
    tf.mu.Lock()
    defer tf.mu.Unlock()
    for _, result := range tf.testResults {
        if result.TestCaseID == testCaseID {
            return result, nil
        }
    }
    return nil, errors.New("test case result not found")
}
