package integration

type SmartContractHook struct {
	HookID      string
	Description string
	Endpoint    string
}

type SmartContractManager struct {
	Hooks map[string]*SmartContractHook
}

func NewSmartContractManager() *SmartContractManager {
	return &SmartContractManager{
		Hooks: make(map[string]*SmartContractHook),
	}
}

func (scm *SmartContractManager) AddHook(hookID, description, endpoint string) {
	scm.Hooks[hookID] = &SmartContractHook{
		HookID:      hookID,
		Description: description,
		Endpoint:    endpoint,
	}
}

func (scm *SmartContractManager) GetHook(hookID string) *SmartContractHook {
	return scm.Hooks[hookID]
}

func (scm *SmartContractManager) ListHooks() []*SmartContractHook {
	var hooks []*SmartContractHook
	for _, hook := range scm.Hooks {
		hooks = append(hooks, hook)
	}
	return hooks
}

func (scm *SmartContractManager) RemoveHook(hookID string) {
	delete(scm.Hooks, hookID)
}
