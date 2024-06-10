package smart_contract_templates

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
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
			if fmt.Sprintf("%T", value) != fmt.Sprintf("%T", paramValue) {
				return fmt.Errorf("parameter %s should be of type %T", key, value)
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

// VerifyTemplate ensures the integrity and security of a smart contract template
func VerifyTemplate(template *SmartContractTemplate) error {
	// Example validation logic (real logic would be more comprehensive)
	if template.Name == "" || template.Code == "" {
		return errors.New("template name and code must not be empty")
	}
	// Further validation logic as needed
	return nil
}

// DeployTemplate deploys the smart contract template to the blockchain
func DeployTemplate(template *SmartContractTemplate, params map[string]interface{}) (string, error) {
	// Example deployment logic (real logic would involve actual blockchain interaction)
	parameterizedTemplate, err := NewTemplateLibrary().ParameterizeTemplate(template.Name, params)
	if err != nil {
		return "", err
	}

	// Simulate compilation of the smart contract
	compiledCode, err := compileSmartContract(parameterizedTemplate.Code)
	if err != nil {
		return "", err
	}

	// Simulate deployment (e.g., sending compiled code to a blockchain network)
	txID := simulateDeployment(compiledCode)
	return txID, nil
}

// compileSmartContract simulates the compilation of a smart contract
func compileSmartContract(code string) (string, error) {
	cmd := exec.Command("solc", "--bin", "-")
	cmd.Stdin = bytes.NewBufferString(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to compile smart contract: %v", err)
	}
	return out.String(), nil
}

// simulateDeployment simulates the deployment of a smart contract to a blockchain
func simulateDeployment(compiledCode string) string {
	// Example: Generate a pseudo transaction ID based on the compiled code
	hash := sha256.Sum256([]byte(compiledCode))
	return fmt.Sprintf("%x", hash)
}

// TemplateMarket represents a marketplace for discovering, sharing, and exchanging smart contract templates
type TemplateMarket struct {
	Library *TemplateLibrary
}

// NewTemplateMarket initializes a new template marketplace
func NewTemplateMarket() *TemplateMarket {
	return &TemplateMarket{
		Library: NewTemplateLibrary(),
	}
}

// ListTemplates lists all templates available in the marketplace
func (market *TemplateMarket) ListTemplates() []string {
	var templateNames []string
	for name := range market.Library.Templates {
		templateNames = append(templateNames, name)
	}
	return templateNames
}

// ShareTemplate allows a user to share a new template in the marketplace
func (market *TemplateMarket) ShareTemplate(template *SmartContractTemplate) error {
	if err := VerifyTemplate(template); err != nil {
		return err
	}
	return market.Library.AddTemplate(template)
}

// FetchTemplate fetches a template from the marketplace
func (market *TemplateMarket) FetchTemplate(name string) (*SmartContractTemplate, error) {
	return market.Library.GetTemplate(name)
}

// ServeMarketplace serves the template marketplace over HTTP
func (market *TemplateMarket) ServeMarketplace(port string) error {
	http.HandleFunc("/templates", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			templates := market.ListTemplates()
			json.NewEncoder(w).Encode(templates)
		case http.MethodPost:
			var template SmartContractTemplate
			if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := market.ShareTemplate(&template); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/templates/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := r.URL.Path[len("/templates/"):]
		template, err := market.FetchTemplate(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(template)
	})

	return http.ListenAndServe(":"+port, nil)
}

// Example usage
func main() {
	// Initialize a new template marketplace
	market := NewTemplateMarket()

	// Create a new template
	template := &SmartContractTemplate{
		Name: "TokenContract",
		Parameters: map[string]interface{}{
			"tokenName":    "string",
			"initialSupply": int64(0),
		},
		Code: "contract Token { ... }",
	}

	// Share the template in the marketplace
	err := market.ShareTemplate(template)
	if err != nil {
		fmt.Println("Error sharing template:", err)
		return
	}

	// List available templates
	templates := market.ListTemplates()
	fmt.Println("Available templates:", templates)

	// Fetch a template
	fetchedTemplate, err := market.FetchTemplate("TokenContract")
	if err != nil {
		fmt.Println("Error fetching template:", err)
		return
	}
	fmt.Println("Fetched template:", fetchedTemplate)

	// Start serving the marketplace
	err = market.ServeMarketplace("8080")
	if err != nil {
		fmt.Println("Error serving marketplace:", err)
	}
}
