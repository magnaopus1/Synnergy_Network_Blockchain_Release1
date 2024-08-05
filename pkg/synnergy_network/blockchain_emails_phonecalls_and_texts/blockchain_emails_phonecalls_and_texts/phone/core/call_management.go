package core

type CallManagement struct {
	CallManager *CallManager
}

func NewCallManagement() *CallManagement {
	return &CallManagement{
		CallManager: NewCallManager(),
	}
}

func (cm *CallManagement) InitiateCall(id, from, to string) {
	cm.CallManager.StartCall(id, from, to)
}

func (cm *CallManagement) TerminateCall(id string) error {
	return cm.CallManager.EndCall(id)
}

func (cm *CallManagement) ActiveCalls() []*Call {
	return cm.CallManager.GetActiveCalls()
}

func (cm *CallManagement) CallHistory() []*Call {
	return cm.CallManager.GetCallHistory()
}
