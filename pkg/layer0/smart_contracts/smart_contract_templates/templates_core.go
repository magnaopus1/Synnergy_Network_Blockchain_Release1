package smart_contract_templates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// SmartContractTemplate represents a template for a smart contract
type SmartContractTemplate struct {
	Name       string
	Parameters map[string]interface{}
	Code       string
	Hash       string
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

// AddTemplate adds a new template to the library after verifying it
func (lib *TemplateLibrary) AddTemplate(template *SmartContractTemplate) error {
	if _, exists := lib.Templates[template.Name]; exists {
		return errors.New("template already exists in the library")
	}
	if err := VerifyTemplate(template); err != nil {
		return err
	}
	template.Hash = GenerateTemplateHash(template)
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

// VerifyTemplate ensures the integrity and security of a smart contract template
func VerifyTemplate(template *SmartContractTemplate) error {
	if template.Name == "" {
		return errors.New("template name must not be empty")
	}
	if template.Code == "" {
		return errors.New("template code must not be empty")
	}
	if err := verifyTemplateCodeSyntax(template.Code); err != nil {
		return err
	}
	if err := verifyTemplateParameters(template.Parameters); err != nil {
		return err
	}
	return nil
}

// verifyTemplateCodeSyntax performs a basic syntax check on the template code
func verifyTemplateCodeSyntax(code string) error {
	if len(code) < 10 {
		return errors.New("template code is too short to be valid")
	}
	if !regexp.MustCompile(`(?i)contract`).MatchString(code) {
		return errors.New("template code does not contain a valid contract")
	}
	return nil
}

// verifyTemplateParameters ensures that template parameters are valid
func verifyTemplateParameters(params map[string]interface{}) error {
	for key, value := range params {
		switch value.(type) {
		case string, int, int64, float64, bool:
			continue
		default:
			return fmt.Errorf("parameter %s has an invalid type %T", key, value)
		}
	}
	return nil
}

// GenerateTemplateHash generates a SHA-256 hash of the template's code and parameters
func GenerateTemplateHash(template *SmartContractTemplate) string {
	data := template.Code + fmt.Sprintf("%v", template.Parameters)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
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
			"tokenName":    "MyToken",
			"initialSupply": int64(1000000),
		},
		Code: "contract Token { ... }",
	}

	// Verify and add the template to the library
	err := lib.AddTemplate(template)
	if err != nil {
		fmt.Println("Error adding template:", err)
		return
	}

	// List available templates
	fmt.Println("Available templates:", lib.Templates)

	// Fetch a template
	fetchedTemplate, err := lib.GetTemplate("TokenContract")
	if err != nil {
		fmt.Println("Error fetching template:", err)
		return
	}
	fmt.Println("Fetched template:", fetchedTemplate)

	// Serialize the template
	serializedTemplate, err := SerializeTemplate(fetchedTemplate)
	if err != nil {
		fmt.Println("Error serializing template:", err)
		return
	}
	fmt.Println("Serialized template:", serializedTemplate)

	// Deserialize the template
	deserializedTemplate, err := DeserializeTemplate(serializedTemplate)
	if err != nil {
		fmt.Println("Error deserializing template:", err)
		return
	}
	fmt.Println("Deserialized template:", deserializedTemplate)
}
