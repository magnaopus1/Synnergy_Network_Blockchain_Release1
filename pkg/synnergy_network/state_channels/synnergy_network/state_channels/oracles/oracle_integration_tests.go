package oracles

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDecentralizedOracle(t *testing.T) {
	dataSources := []string{"sourceA", "sourceB"}
	oracle := NewDecentralizedOracle("oracle1", dataSources)

	assert.Equal(t, "oracle1", oracle.OracleID)
	assert.Equal(t, dataSources, oracle.DataSources)
	assert.Equal(t, OracleActive, oracle.Status)
}

func TestCollectData(t *testing.T) {
	dataSources := []string{"sourceA", "sourceB"}
	oracle := NewDecentralizedOracle("oracle1", dataSources)

	err := oracle.CollectData()
	assert.Nil(t, err)
	assert.NotNil(t, oracle.CollectedData)
}

func TestDeactivateOracle(t *testing.T) {
	dataSources := []string{"sourceA", "sourceB"}
	oracle := NewDecentralizedOracle("oracle1", dataSources)

	err := oracle.DeactivateOracle()
	assert.Nil(t, err)
	assert.Equal(t, OracleInactive, oracle.Status)
}

func TestEncryptDecryptOracleData(t *testing.T) {
	dataSources := []string{"sourceA", "sourceB"}
	oracle := NewDecentralizedOracle("oracle1", dataSources)
	oracle.CollectData()
	key := []byte("encryptionkey123")

	encrypted, err := oracle.EncryptOracleData(key)
	assert.Nil(t, err)

	newOracle := &DecentralizedOracle{}
	err = newOracle.DecryptOracleData(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, oracle.OracleID, newOracle.OracleID)
	assert.Equal(t, oracle.CollectedData, newOracle.CollectedData)
	assert.Equal(t, oracle.Status, newOracle.Status)
}
