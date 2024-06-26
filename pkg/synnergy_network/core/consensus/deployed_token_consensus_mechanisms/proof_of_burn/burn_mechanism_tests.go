package proof_of_burn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBurnTokens tests the BurnTokens function for various scenarios.
func TestBurnTokens(t *testing.T) {
	burner := NewSimpleBurner("dummyPrivateKey", "dummyPublicKey")

	// Test cases
	tests := []struct {
		name       string
		record     BurnRecord
		wantErr    bool
		errorMsg   string
	}{
		{
			name: "Valid burn",
			record: BurnRecord{
				TokenID:   "Token123",
				Amount:    100,
				BurnerID:  "Burner1",
				Timestamp: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "Invalid amount - zero",
			record: BurnRecord{
				TokenID:   "Token123",
				Amount:    0,
				BurnerID:  "Burner1",
				Timestamp: time.Now(),
			},
			wantErr:    true,
			errorMsg:   "invalid amount: amount must be positive",
		},
		{
			name: "Invalid amount - negative",
			record: BurnRecord{
				TokenID:   "Token123",
				Amount:    -50,
				BurnerID:  "Burner1",
				Timestamp: time.Now(),
			},
			wantErr:    true,
			errorMsg:   "invalid amount: amount must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := burner.BurnTokens(tt.record)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.errorMsg, err.Error())
			} else {
				assert.NoError(t, err)
				// Verify the signature to ensure it's correct
				assert.True(t, burner.VerifyBurn(tt.record), "Burn verification failed")
			}
		})
	}
}

// TestVerifyBurn tests the VerifyBurn function to ensure it accurately verifies burn records.
func TestVerifyBurn(t *testing.T) {
	burner := NewSimpleBurner("dummyPrivateKey", "dummyPublicKey")
	record := BurnRecord{
		TokenID:   "Token123",
		Amount:    100,
		BurnerID:  "Burner1",
		Timestamp: time.Now(),
	}

	// Simulate correct burning
	err := burner.BurnTokens(record)
	assert.NoError(t, err)

	// Check verification
	valid := burner.VerifyBurn(record)
	assert.True(t, valid, "Verification should pass for a valid burn")

	// Modify the record to simulate tampering
	record.Amount = 200
	invalid := burner.VerifyBurn(record)
	assert.False(t, invalid, "Verification should fail for a tampered record")
}
