package behavioural_proof

import (
    "testing"
    "time"
)

func TestRegisterValidator(t *testing.T) {
    bp := NewBehaviouralProof()
    err := bp.RegisterValidator("validator1")
    if err != nil {
        t.Errorf("Error registering validator: %s", err)
    }
    if _, exists := bp.validators["validator1"]; !exists {
        t.Errorf("Validator 'validator1' was not registered correctly")
    }
}

func TestUpdateValidatorScores(t *testing.T) {
    bp := NewBehaviouralProof()
    _ = bp.RegisterValidator("validator1")
    err := bp.UpdateValidatorScores("validator1", 90.0, 95.0, 85.0)
    if err != nil {
        t.Errorf("Error updating scores: %s", err)
    }
    v := bp.validators["validator1"]
    if v.UptimeScore != 90.0 || v.AccuracyScore != 95.0 || v.CommunityContributionScore != 85.0 {
        t.Errorf("Scores were not updated correctly")
    }
}

func TestReputationCalculation(t *testing.T) {
    bp := NewBehaviouralProof()
    _ = bp.RegisterValidator("validator1")
    _ = bp.UpdateValidatorScores("validator1", 100, 100, 100)
    expectedScore := 100*bp.weightingFactors.UptimeWeight +
        100*bp.weightingFactors.AccuracyWeight +
        100*bp.weightingFactors.CommunityWeight
    if bp.validators["validator1"].ReputationScore != expectedScore {
        t.Errorf("Expected reputation score of %f, but got %f", expectedScore, bp.validators["validator1"].ReputationScore)
    }
}

func TestPenaltyApplication(t *testing.T) {
    bp := NewBehaviouralProof()
    _ = bp.RegisterValidator("validator1")
    _ = bp.UpdateValidatorScores("validator1", 100, 100, 100)
    _ = bp.ApplyPenalties("validator1", "downtime")
    if bp.validators["validator1"].ReputationScore >= 100 {
        t.Errorf("Penalty was not applied correctly, expected lower score")
    }
}

func TestValidatorSelection(t *testing.T) {
    bp := NewBehaviouralProof()
    _ = bp.RegisterValidator("validator1")
    _ = bp.UpdateValidatorScores("validator1", 100, 100, 100)
    _ = bp.RegisterValidator("validator2")
    _ = bp.UpdateValidatorScores("validator2", 80, 90, 95)

    validators, err := bp.SelectValidators(1)
    if err != nil {
        t.Errorf("Error selecting validators: %s", err)
    }
    if len(validators) != 1 || validators[0].ID != "validator1" {
        t.Errorf("Incorrect validators selected")
    }
}

func TestReputationRecovery(t *testing.T) {
    bp := NewBehaviouralProof()
    _ = bp.RegisterValidator("validator1")
    _ = bp.UpdateValidatorScores("validator1", 50, 60, 70)
    _ = bp.ApplyPenalties("validator1", "downtime")
    originalScore := bp.validators["validator1"].ReputationScore

    // Simulate recovery
    _ = bp.UpdateValidatorScores("validator1", 80, 85, 90)
    if bp.validators["validator1"].ReputationScore <= originalScore {
        t.Errorf("Reputation did not recover as expected")
    }
}

func BenchmarkUpdateValidatorScores(b *testing.B) {
    bp := NewBehaviouralProof()
    _ = bp.RegisterValidator("validator1")
    for i := 0; i < b.N; i++ {
        _ = bp.UpdateValidatorScores("validator1", 90.0, 95.0, 85.0)
    }
}

func BenchmarkValidatorSelection(b *testing.B) {
    bp := NewBehaviouralProof()
    for i := 0; i < 100; i++ {
        validatorID := "validator" + string(i)
        _ = bp.RegisterValidator(validatorID)
        _ = bp.UpdateValidatorScores(validatorID, float64(i), float64(i), float64(i))
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = bp.SelectValidators(10)
    }
}
