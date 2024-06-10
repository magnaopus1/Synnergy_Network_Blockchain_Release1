package automateddecisionmaking

import (
    "testing"
    "reflect"
)

// TestDecisionEngineInitialization tests the initialization process of the DecisionEngine to ensure it loads rules correctly.
func TestDecisionEngineInitialization(t *testing.T) {
    rulesJson := `{"transactionPriority": "maximize", "securityLevel": "enhance"}`
    engine, err := NewDecisionEngine(rulesJson)
    if err != nil {
        t.Errorf("Failed to initialize DecisionEngine: %s", err)
    }

    expectedRules := map[string]interface{}{
        "transactionPriority": "maximize",
        "securityLevel": "enhance",
    }

    if !reflect.DeepEqual(engine.Rules, expectedRules) {
        t.Errorf("DecisionEngine rules not initialized correctly. Expected %+v, got %+v", expectedRules, engine.Rules)
    }
}

// TestEvaluateDecision tests the decision-making process for various scenarios.
func TestEvaluateDecision(t *testing.T) {
    engine, _ := NewDecisionEngine(`{"costEfficiency": "maximize", "responseTime": "minimize"}`)
    testData := map[string]interface{}{
        "costEfficiency": 80,
        "responseTime": 20,
    }

    expectedDecision := map[string]interface{}{
        "costEfficiency": 80, // Expect the same value as input, testing rule logic is needed here.
        "responseTime": 20,   // As above, assumes "minimize" would alter this in a real scenario.
    }

    decisionResult, _ := engine.EvaluateDecision(testData)
    if !reflect.DeepEqual(decisionResult, expectedDecision) {
        t.Errorf("EvaluateDecision did not return expected results. Expected %+v, got %+v", expectedDecision, decisionResult)
    }
}

// TestEncryptionOfSensitiveData ensures that the encryption mechanism is functional and secure.
func TestEncryptionOfSensitiveData(t *testing.T) {
    engine := DecisionEngine{}
    testData := "sensitive data"
    encryptedData, err := engine.EncryptSensitiveData([]byte(testData))
    if err != nil {
        t.Errorf("Encryption failed: %s", err)
    }

    if reflect.DeepEqual(encryptedData, []byte(testData)) {
        t.Errorf("Encryption did not alter the data, which it should have.")
    }
}

// Additional tests here can include load testing, stress testing, and simulation of decision impacts on blockchain performance.
