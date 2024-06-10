package configuration

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"sync"
	"log"
	"time"
)

// Template represents a configuration template
type Template struct {
	Name   string                 `json:"name"`
	Config map[string]interface{} `json:"config"`
}

// TemplateEngine manages configuration templates
type TemplateEngine struct {
	templates map[string]*Template
	mutex     sync.RWMutex
}

// NewTemplateEngine creates a new instance of TemplateEngine
func NewTemplateEngine() *TemplateEngine {
	return &TemplateEngine{
		templates: make(map[string]*Template),
	}
}

// AddTemplate adds a new template to the engine
func (te *TemplateEngine) AddTemplate(template *Template) error {
	te.mutex.Lock()
	defer te.mutex.Unlock()

	if _, exists := te.templates[template.Name]; exists {
		return errors.New("template already exists")
	}

	te.templates[template.Name] = template
	log.Printf("Template %s added\n", template.Name)

	return nil
}

// UpdateTemplate updates an existing template
func (te *TemplateEngine) UpdateTemplate(template *Template) error {
	te.mutex.Lock()
	defer te.mutex.Unlock()

	if _, exists := te.templates[template.Name]; !exists {
		return errors.New("template does not exist")
	}

	te.templates[template.Name] = template
	log.Printf("Template %s updated\n", template.Name)

	return nil
}

// RemoveTemplate removes a template by name
func (te *TemplateEngine) RemoveTemplate(name string) error {
	te.mutex.Lock()
	defer te.mutex.Unlock()

	if _, exists := te.templates[name]; !exists {
		return errors.New("template does not exist")
	}

	delete(te.templates, name)
	log.Printf("Template %s removed\n", name)

	return nil
}

// GetTemplate retrieves a template by name
func (te *TemplateEngine) GetTemplate(name string) (*Template, error) {
	te.mutex.RLock()
	defer te.mutex.RUnlock()

	template, exists := te.templates[name]
	if !exists {
		return nil, errors.New("template not found")
	}

	return template, nil
}

// ListTemplates lists all available templates
func (te *TemplateEngine) ListTemplates() []*Template {
	te.mutex.RLock()
	defer te.mutex.RUnlock()

	var templates []*Template
	for _, template := range te.templates {
		templates = append(templates, template)
	}

	return templates
}

// SaveTemplateToFile saves a template to a file
func (te *TemplateEngine) SaveTemplateToFile(name, filename string) error {
	te.mutex.RLock()
	defer te.mutex.RUnlock()

	template, exists := te.templates[name]
	if !exists {
		return errors.New("template not found")
	}

	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// LoadTemplateFromFile loads a template from a file
func (te *TemplateEngine) LoadTemplateFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var template Template
	if err := json.Unmarshal(data, &template); err != nil {
		return err
	}

	te.mutex.Lock()
	defer te.mutex.Unlock()

	te.templates[template.Name] = &template
	log.Printf("Template %s loaded from file\n", template.Name)

	return nil
}

// ValidateTemplate validates the configuration of a template
func ValidateTemplate(template *Template) error {
	if template.Name == "" {
		return errors.New("template name is required")
	}
	if template.Config == nil {
		return errors.New("template config is required")
	}
	return nil
}

// InitTemplateEngine initializes the TemplateEngine with initial templates
func InitTemplateEngine(initialTemplates []*Template) (*TemplateEngine, error) {
	engine := NewTemplateEngine()

	for _, template := range initialTemplates {
		if err := ValidateTemplate(template); err != nil {
			return nil, err
		}

		if err := engine.AddTemplate(template); err != nil {
			return nil, err
		}
	}

	return engine, nil
}

// ApplyTemplate applies a template to a specific configuration
func (te *TemplateEngine) ApplyTemplate(templateName string, config map[string]interface{}) error {
	te.mutex.RLock()
	defer te.mutex.RUnlock()

	template, exists := te.templates[templateName]
	if !exists {
		return errors.New("template not found")
	}

	for key, value := range template.Config {
		config[key] = value
	}

	log.Printf("Template %s applied\n", templateName)
	return nil
}

// MonitorTemplateUsage monitors the usage of templates and logs any issues
func (te *TemplateEngine) MonitorTemplateUsage(interval time.Duration) {
	for {
		time.Sleep(interval)
		te.mutex.RLock()
		for name, template := range te.templates {
			log.Printf("Monitoring template: %s, config: %v\n", name, template.Config)
		}
		te.mutex.RUnlock()
	}
}

// Example of usage
func main() {
	// Example templates
	templates := []*Template{
		{
			Name: "Development",
			Config: map[string]interface{}{
				"host": "localhost",
				"port": 8080,
			},
		},
		{
			Name: "Production",
			Config: map[string]interface{}{
				"host": "prod.example.com",
				"port": 443,
			},
		},
	}

	// Initialize template engine
	engine, err := InitTemplateEngine(templates)
	if err != nil {
		log.Fatalf("Failed to initialize template engine: %v", err)
	}

	// List templates
	for _, template := range engine.ListTemplates() {
		log.Printf("Template: %s, Config: %v\n", template.Name, template.Config)
	}

	// Save a template to file
	if err := engine.SaveTemplateToFile("Development", "development_template.json"); err != nil {
		log.Fatalf("Failed to save template to file: %v", err)
	}

	// Load a template from file
	if err := engine.LoadTemplateFromFile("development_template.json"); err != nil {
		log.Fatalf("Failed to load template from file: %v", err)
	}

	// List templates again to verify loading
	for _, template := range engine.ListTemplates() {
		log.Printf("Template: %s, Config: %v\n", template.Name, template.Config)
	}

	// Example configuration
	config := map[string]interface{}{
		"host": "default",
		"port": 80,
	}

	// Apply template to configuration
	if err := engine.ApplyTemplate("Development", config); err != nil {
		log.Fatalf("Failed to apply template: %v", err)
	}

	log.Printf("Updated config: %v\n", config)

	// Start monitoring template usage
	go engine.MonitorTemplateUsage(10 * time.Second)

	// Keep the main function running
	select {}
}
