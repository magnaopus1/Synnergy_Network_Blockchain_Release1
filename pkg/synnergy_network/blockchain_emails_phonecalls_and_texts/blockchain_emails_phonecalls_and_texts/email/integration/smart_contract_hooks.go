package integration

import (
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "net/http"
    "time"
    "sync"
)

// SmartContractHook represents a hook that triggers a specific function in a smart contract
type SmartContractHook struct {
    Name       string
    URL        string
    Method     string
    Headers    map[string]string
    Payload    map[string]interface{}
    RetryCount int
    RetryDelay time.Duration
}

// SmartContractHookManager manages the hooks for smart contracts
type SmartContractHookManager struct {
    hooks       map[string]SmartContractHook
    hooksMutex  sync.RWMutex
    httpClient  *http.Client
}

// NewSmartContractHookManager creates a new SmartContractHookManager
func NewSmartContractHookManager() *SmartContractHookManager {
    return &SmartContractHookManager{
        hooks: make(map[string]SmartContractHook),
        httpClient: &http.Client{
            Timeout: time.Second * 10,
        },
    }
}

// AddHook adds a new hook
func (m *SmartContractHookManager) AddHook(name string, hook SmartContractHook) {
    m.hooksMutex.Lock()
    defer m.hooksMutex.Unlock()
    m.hooks[name] = hook
}

// RemoveHook removes a hook
func (m *SmartContractHookManager) RemoveHook(name string) {
    m.hooksMutex.Lock()
    defer m.hooksMutex.Unlock()
    delete(m.hooks, name)
}

// TriggerHook triggers a specific hook
func (m *SmartContractHookManager) TriggerHook(name string) error {
    m.hooksMutex.RLock()
    hook, exists := m.hooks[name]
    m.hooksMutex.RUnlock()

    if !exists {
        return errors.New("hook not found")
    }

    var err error
    for i := 0; i <= hook.RetryCount; i++ {
        err = m.executeHook(hook)
        if err == nil {
            break
        }
        time.Sleep(hook.RetryDelay)
    }

    return err
}

// executeHook executes the hook
func (m *SmartContractHookManager) executeHook(hook SmartContractHook) error {
    payload, err := json.Marshal(hook.Payload)
    if err != nil {
        return err
    }

    req, err := http.NewRequest(hook.Method, hook.URL, ioutil.NopCloser(bytes.NewBuffer(payload)))
    if err != nil {
        return err
    }

    for key, value := range hook.Headers {
        req.Header.Set(key, value)
    }

    resp, err := m.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return err
    }

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("error triggering hook: %s", string(body))
    }

    return nil
}

// ListHooks lists all the hooks
func (m *SmartContractHookManager) ListHooks() []string {
    m.hooksMutex.RLock()
    defer m.hooksMutex.RUnlock()

    var hooks []string
    for name := range m.hooks {
        hooks = append(hooks, name)
    }
    return hooks
}

// GetHook gets a specific hook by name
func (m *SmartContractHookManager) GetHook(name string) (SmartContractHook, error) {
    m.hooksMutex.RLock()
    defer m.hooksMutex.RUnlock()

    hook, exists := m.hooks[name]
    if !exists {
        return SmartContractHook{}, errors.New("hook not found")
    }

    return hook, nil
}
