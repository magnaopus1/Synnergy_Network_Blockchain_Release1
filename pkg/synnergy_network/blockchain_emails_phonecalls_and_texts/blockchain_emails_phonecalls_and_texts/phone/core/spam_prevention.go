package core

import (
	"errors"
	"strings"
)

type SpamPrevention struct {
	BlockedNumbers map[string]bool
}

func NewSpamPrevention() *SpamPrevention {
	return &SpamPrevention{
		BlockedNumbers: make(map[string]bool),
	}
}

func (sp *SpamPrevention) BlockNumber(number string) {
	sp.BlockedNumbers[number] = true
}

func (sp *SpamPrevention) UnblockNumber(number string) {
	delete(sp.BlockedNumbers, number)
}

func (sp *SpamPrevention) IsBlocked(number string) bool {
	return sp.BlockedNumbers[number]
}

func (sp *SpamPrevention) FilterSpamCalls(calls []*Call) ([]*Call, error) {
	if len(calls) == 0 {
		return nil, errors.New("no calls to filter")
	}
	var filteredCalls []*Call
	for _, call := range calls {
		if !sp.IsBlocked(call.From) && !sp.IsBlocked(call.To) {
			filteredCalls = append(filteredCalls, call)
		}
	}
	return filteredCalls, nil
}
