package common

// StateManager manages the state of the system.
type StateManager struct {
    State string
}

func NewStateManager(state string) *StateManager {
    return &StateManager{
        State: state,
    }
}