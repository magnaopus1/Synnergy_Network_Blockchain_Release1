package crosschain

import (
	"fmt"
	"sync"
)

// ProtocolTranslator defines the interface for translating data between different blockchain protocols.
type ProtocolTranslator interface {
	TranslateData(data interface{}, targetProtocol string) (interface{}, error)
}

// DynamicProtocolTranslator manages the translation of data across different blockchain protocols dynamically.
type DynamicProtocolTranslator struct {
	translators map[string]ProtocolTranslator
	mu          sync.RWMutex
}

// NewDynamicProtocolTranslator creates a new instance of DynamicProtocolTranslator.
func NewDynamicProtocolTranslator() *DynamicProtocolTranslator {
	return &DynamicProtocolTranslator{
		translators: make(map[string]ProtocolTranslator),
	}
}

// RegisterTranslator registers a new translator for a specific blockchain protocol.
func (dpt *DynamicProtocolTranslator) RegisterTranslator(protocolName string, translator ProtocolTranslator) error {
	dpt.mu.Lock()
	defer dpt.mu.Unlock()

	if _, exists := dpt.translators[protocolName]; exists {
		return fmt.Errorf("translator for protocol %s already registered", protocolName)
	}

	dpt.translators[protocolName] = translator
	return nil
}

// UnregisterTranslator removes a translator for a specific blockchain protocol.
func (dpt *DynamicProtocolTranslator) UnregisterTranslator(protocolName string) error {
	dpt.mu.Lock()
	defer dpt.mu.Unlock()

	if _, exists := dpt.translators[protocolName]; !exists {
		return fmt.Errorf("translator for protocol %s not found", protocolName)
	}

	delete(dpt.translators, protocolName)
	return nil
}

// Translate adapts data from one blockchain protocol to another.
func (dpt *DynamicProtocolTranslator) Translate(sourceData interface{}, sourceProtocol, targetProtocol string) (interface{}, error) {
	dpt.mu.RLock()
	defer dpt.mu.RUnlock()

	translator, exists := dpt.translators[targetProtocol]
	if !exists {
		return nil, fmt.Errorf("no translator available for target protocol %s", targetProtocol)
	}

	transformedData, err := translator.TranslateData(sourceData, targetProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to translate data to %s: %v", targetProtocol, err)
	}

	return transformedData, nil
}

// Example of a specific protocol translator
type ExampleProtocolTranslator struct{}

func (e *ExampleProtocolTranslator) TranslateData(data interface{}, targetProtocol string) (interface{}, error) {
	// Logic to transform data to the target protocol's format
	return data, nil
}

func main() {
	dpt := NewDynamicProtocolTranslator()
	err := dpt.RegisterTranslator("ExampleProtocol", &ExampleProtocolTranslator{})
	if err != nil {
		fmt.Println("Error registering translator:", err)
		return
	}

	// Example translation process
	sourceData := "example data"
	transformedData, err := dpt.Translate(sourceData, "CurrentProtocol", "ExampleProtocol")
	if err != nil {
		fmt.Println("Error translating data:", err)
		return
	}

	fmt.Printf("Translated data: %v\n", transformedData)
}
