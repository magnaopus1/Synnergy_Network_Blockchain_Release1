package identity

import (
	"errors"
	"time"
)

type BiometricData struct {
	ID        string
	Timestamp time.Time
	Data      []byte
}

type BiometricAuth struct {
	DataStore map[string]*BiometricData
}

func NewBiometricAuth() *BiometricAuth {
	return &BiometricAuth{
		DataStore: make(map[string]*BiometricData),
	}
}

func (ba *BiometricAuth) AddBiometricData(id string, data []byte) {
	ba.DataStore[id] = &BiometricData{
		ID:        id,
		Timestamp: time.Now(),
		Data:      data,
	}
}

func (ba *BiometricAuth) VerifyBiometricData(id string, data []byte) (bool, error) {
	bioData, exists := ba.DataStore[id]
	if !exists {
		return false, errors.New("biometric data not found")
	}
	if string(bioData.Data) != string(data) {
		return false, errors.New("biometric data does not match")
	}
	return true, nil
}
