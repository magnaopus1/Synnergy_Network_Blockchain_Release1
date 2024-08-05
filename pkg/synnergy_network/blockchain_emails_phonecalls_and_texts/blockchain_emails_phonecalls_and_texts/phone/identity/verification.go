package identity

import (
	"errors"
)

type VerificationCode struct {
	UserID string
	Code   string
}

type VerificationManager struct {
	Codes map[string]*VerificationCode
}

func NewVerificationManager() *VerificationManager {
	return &VerificationManager{
		Codes: make(map[string]*VerificationCode),
	}
}

func (vm *VerificationManager) GenerateVerificationCode(userID, code string) {
	vm.Codes[userID] = &VerificationCode{
		UserID: userID,
		Code:   code,
	}
}

func (vm *VerificationManager) VerifyCode(userID, code string) (bool, error) {
	verificationCode, exists := vm.Codes[userID]
	if !exists {
		return false, errors.New("verification code not found")
	}
	if verificationCode.Code != code {
		return false, errors.New("verification code does not match")
	}
	return true, nil
}

func (vm *VerificationManager) InvalidateCode(userID string) {
	delete(vm.Codes, userID)
}
