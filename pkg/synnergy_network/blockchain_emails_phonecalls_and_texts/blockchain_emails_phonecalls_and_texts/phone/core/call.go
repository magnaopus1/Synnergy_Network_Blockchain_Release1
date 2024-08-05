package core

import (
	"errors"
	"time"
)

type Call struct {
	ID        string
	From      string
	To        string
	StartTime time.Time
	EndTime   time.Time
}

func NewCall(id, from, to string) *Call {
	return &Call{
		ID:        id,
		From:      from,
		To:        to,
		StartTime: time.Now(),
	}
}

func (c *Call) EndCall() {
	c.EndTime = time.Now()
}

func (c *Call) Duration() time.Duration {
	return c.EndTime.Sub(c.StartTime)
}

type CallManager struct {
	ActiveCalls map[string]*Call
	CallHistory map[string]*Call
}

func NewCallManager() *CallManager {
	return &CallManager{
		ActiveCalls: make(map[string]*Call),
		CallHistory: make(map[string]*Call),
	}
}

func (cm *CallManager) StartCall(id, from, to string) {
	call := NewCall(id, from, to)
	cm.ActiveCalls[id] = call
}

func (cm *CallManager) EndCall(id string) error {
	call, exists := cm.ActiveCalls[id]
	if !exists {
		return errors.New("call not found")
	}
	call.EndCall()
	cm.CallHistory[id] = call
	delete(cm.ActiveCalls, id)
	return nil
}

func (cm *CallManager) GetCallHistory() []*Call {
	var history []*Call
	for _, call := range cm.CallHistory {
		history = append(history, call)
	}
	return history
}

func (cm *CallManager) GetActiveCalls() []*Call {
	var active []*Call
	for _, call := range cm.ActiveCalls {
		active = append(active, call)
	}
	return active
}
