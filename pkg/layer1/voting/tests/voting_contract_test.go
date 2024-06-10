package voting

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestVotingContract(t *testing.T) {
    // Initialize the contract with candidate names
    candidateNames := []string{"Candidate1", "Candidate2", "Candidate3"}
    contract := NewVotingContract(candidateNames)

    // Ensure the contract has the correct number of candidates
    assert.Equal(t, len(candidateNames), contract.GetCandidateCount(), "Incorrect candidate count")

    // Vote for a candidate
    voterAddress := "0xAddress1"
    candidateIndex := uint256(1) // Vote for Candidate2
    contract.Vote(voterAddress, candidateIndex)

    // Verify that the vote was recorded
    hasVoted, err := contract.HasVoted(voterAddress)
    require.NoError(t, err, "Error checking if the voter has voted")
    assert.True(t, hasVoted, "Voter should have voted")

    // Get the vote count for the candidate
    voteCount, err := contract.GetVoteCount(candidateIndex)
    require.NoError(t, err, "Error getting vote count")
    assert.Equal(t, uint256(1), voteCount, "Incorrect vote count")

    // Check the vote count for all candidates
    for i, name := range candidateNames {
        count, err := contract.GetVoteCount(uint256(i))
        require.NoError(t, err, "Error getting vote count")
        if i == int(candidateIndex) {
            assert.Equal(t, uint256(1), count, "Incorrect vote count for "+name)
        } else {
            assert.Equal(t, uint256(0), count, "Incorrect vote count for "+name)
        }
    }
}
