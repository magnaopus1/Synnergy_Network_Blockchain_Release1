package smart_contract_templates

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// SmartContractTemplate represents a template for a smart contract
type SmartContractTemplate struct {
	Name       string
	Parameters map[string]interface{}
	Code       string
}

// TemplateLibrary represents a collection of smart contract templates
type TemplateLibrary struct {
	Templates map[string]*SmartContractTemplate
}

// NewTemplateLibrary initializes a new template library
func NewTemplateLibrary() *TemplateLibrary {
	return &TemplateLibrary{
		Templates: make(map[string]*SmartContractTemplate),
	}
}

// AddTemplate adds a new template to the library
func (lib *TemplateLibrary) AddTemplate(template *SmartContractTemplate) error {
	if _, exists := lib.Templates[template.Name]; exists {
		return errors.New("template already exists in the library")
	}
	lib.Templates[template.Name] = template
	return nil
}

// GetTemplate retrieves a template from the library
func (lib *TemplateLibrary) GetTemplate(name string) (*SmartContractTemplate, error) {
	template, exists := lib.Templates[name]
	if !exists {
		return nil, errors.New("template not found in the library")
	}
	return template, nil
}

// ParameterizeTemplate customizes a template with specific parameters
func (lib *TemplateLibrary) ParameterizeTemplate(name string, params map[string]interface{}) (*SmartContractTemplate, error) {
	template, err := lib.GetTemplate(name)
	if err != nil {
		return nil, err
	}

	parameterizedTemplate := &SmartContractTemplate{
		Name:       template.Name,
		Parameters: make(map[string]interface{}),
		Code:       template.Code,
	}

	for key, value := range template.Parameters {
		if paramValue, exists := params[key]; exists {
			parameterizedTemplate.Parameters[key] = paramValue
		} else {
			parameterizedTemplate.Parameters[key] = value
		}
	}

	if err := lib.validateParameters(template, parameterizedTemplate.Parameters); err != nil {
		return nil, err
	}

	return parameterizedTemplate, nil
}

// validateParameters ensures that the provided parameters are valid for the template
func (lib *TemplateLibrary) validateParameters(template *SmartContractTemplate, params map[string]interface{}) error {
	for key, value := range template.Parameters {
		if paramValue, exists := params[key]; exists {
			if reflect.TypeOf(value) != reflect.TypeOf(paramValue) {
				return fmt.Errorf("parameter %s should be of type %s", key, reflect.TypeOf(value))
			}
		}
	}
	return nil
}

// SerializeTemplate serializes the smart contract template to JSON
func SerializeTemplate(template *SmartContractTemplate) (string, error) {
	data, err := json.Marshal(template)
	if err != nil {
		return "", fmt.Errorf("failed to serialize template: %v", err)
	}
	return string(data), nil
}

// DeserializeTemplate deserializes the smart contract template from JSON
func DeserializeTemplate(data string) (*SmartContractTemplate, error) {
	var template SmartContractTemplate
	if err := json.Unmarshal([]byte(data), &template); err != nil {
		return nil, fmt.Errorf("failed to deserialize template: %v", err)
	}
	return &template, nil
}

// Example usage

func main() {
	// Initialize a new template library
	lib := NewTemplateLibrary()

	// Create a new template
	template := &SmartContractTemplate{
		Name: "TokenContract",
		Parameters: map[string]interface{}{
			"tokenName":    "string",
			"initialSupply": "int64",
		},
		Code: "contract Token { ... }",
	}

	// Add the template to the library
	err := lib.AddTemplate(template)
	if err != nil {
		fmt.Println("Error adding template:", err)
		return
	}

	// Parameterize the template
	params := map[string]interface{}{
		"tokenName":    "MyToken",
		"initialSupply": int64(1000000),
	}

	parameterizedTemplate, err := lib.ParameterizeTemplate("TokenContract", params)
	if err != nil {
		fmt.Println("Error parameterizing template:", err)
		return
	}

	// Serialize the parameterized template
	serializedTemplate, err := SerializeTemplate(parameterizedTemplate)
	if err != nil {
		fmt.Println("Error serializing template:", err)
		return
	}

	fmt.Println("Serialized Template:", serializedTemplate)

	// Deserialize the template
	deserializedTemplate, err := DeserializeTemplate(serializedTemplate)
	if err != nil {
		fmt.Println("Error deserializing template:", err)
		return
	}

	fmt.Println("Deserialized Template:", deserializedTemplate)
}
