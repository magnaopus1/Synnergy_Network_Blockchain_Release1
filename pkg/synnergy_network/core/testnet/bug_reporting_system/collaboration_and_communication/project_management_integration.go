package collaboration_and_communication

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	// Salt and key length settings for Scrypt encryption.
	saltSize   = 16
	keyLength  = 32
	n          = 32768
	r          = 8
	p          = 1
)

// Project represents a project within the project management integration system.
type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Tasks     []Task    `json:"tasks"`
}

// Task represents a task within a project.
type Task struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Assignee    string    `json:"assignee"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ProjectManagementIntegration manages the integration with project management tools.
type ProjectManagementIntegration struct {
	mu       sync.Mutex
	projects map[string]Project
	tasks    map[string]Task
}

// NewProjectManagementIntegration creates a new instance of ProjectManagementIntegration.
func NewProjectManagementIntegration() *ProjectManagementIntegration {
	return &ProjectManagementIntegration{
		projects: make(map[string]Project),
		tasks:    make(map[string]Task),
	}
}

// CreateProject creates a new project.
func (pmi *ProjectManagementIntegration) CreateProject(name, owner string) (Project, error) {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	projectID := generateID()
	now := time.Now()

	project := Project{
		ID:        projectID,
		Name:      name,
		Owner:     owner,
		CreatedAt: now,
		UpdatedAt: now,
	}

	pmi.projects[projectID] = project
	return project, nil
}

// UpdateProject updates an existing project.
func (pmi *ProjectManagementIntegration) UpdateProject(id, name, owner string) (Project, error) {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	project, exists := pmi.projects[id]
	if !exists {
		return Project{}, errors.New("project not found")
	}

	project.Name = name
	project.Owner = owner
	project.UpdatedAt = time.Now()

	pmi.projects[id] = project
	return project, nil
}

// DeleteProject deletes a project.
func (pmi *ProjectManagementIntegration) DeleteProject(id string) error {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	if _, exists := pmi.projects[id]; !exists {
		return errors.New("project not found")
	}

	delete(pmi.projects, id)
	return nil
}

// AddTask adds a new task to a project.
func (pmi *ProjectManagementIntegration) AddTask(projectID, title, description, assignee string) (Task, error) {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	project, exists := pmi.projects[projectID]
	if !exists {
		return Task{}, errors.New("project not found")
	}

	taskID := generateID()
	now := time.Now()

	task := Task{
		ID:          taskID,
		ProjectID:   projectID,
		Title:       title,
		Description: description,
		Assignee:    assignee,
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	project.Tasks = append(project.Tasks, task)
	pmi.projects[projectID] = project
	pmi.tasks[taskID] = task

	return task, nil
}

// UpdateTask updates an existing task.
func (pmi *ProjectManagementIntegration) UpdateTask(id, title, description, assignee, status string) (Task, error) {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	task, exists := pmi.tasks[id]
	if !exists {
		return Task{}, errors.New("task not found")
	}

	task.Title = title
	task.Description = description
	task.Assignee = assignee
	task.Status = status
	task.UpdatedAt = time.Now()

	pmi.tasks[id] = task
	return task, nil
}

// DeleteTask deletes a task.
func (pmi *ProjectManagementIntegration) DeleteTask(id string) error {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	task, exists := pmi.tasks[id]
	if !exists {
		return errors.New("task not found")
	}

	project, exists := pmi.projects[task.ProjectID]
	if !exists {
		return errors.New("project not found")
	}

	for i, t := range project.Tasks {
		if t.ID == id {
			project.Tasks = append(project.Tasks[:i], project.Tasks[i+1:]...)
			break
		}
	}

	pmi.projects[task.ProjectID] = project
	delete(pmi.tasks, id)
	return nil
}

// ListProjects lists all projects.
func (pmi *ProjectManagementIntegration) ListProjects() []Project {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	projects := make([]Project, 0, len(pmi.projects))
	for _, project := range pmi.projects {
		projects = append(projects, project)
	}
	return projects
}

// ListTasks lists all tasks in a project.
func (pmi *ProjectManagementIntegration) ListTasks(projectID string) ([]Task, error) {
	pmi.mu.Lock()
	defer pmi.mu.Unlock()

	project, exists := pmi.projects[projectID]
	if !exists {
		return nil, errors.New("project not found")
	}
	return project.Tasks, nil
}

// ProjectHandler handles HTTP requests for project management.
func (pmi *ProjectManagementIntegration) ProjectHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pmi.handleListProjects(w, r)
	case http.MethodPost:
		pmi.handleCreateProject(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// TaskHandler handles HTTP requests for task management.
func (pmi *ProjectManagementIntegration) TaskHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pmi.handleListTasks(w, r)
	case http.MethodPost:
		pmi.handleAddTask(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (pmi *ProjectManagementIntegration) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects := pmi.ListProjects()
	json.NewEncoder(w).Encode(projects)
}

func (pmi *ProjectManagementIntegration) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Owner string `json:"owner"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	project, err := pmi.CreateProject(req.Name, req.Owner)
	if err != nil {
		http.Error(w, "failed to create project", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(project)
}

func (pmi *ProjectManagementIntegration) handleListTasks(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project_id")
	if projectID == "" {
		http.Error(w, "missing project_id", http.StatusBadRequest)
		return
	}

	tasks, err := pmi.ListTasks(projectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(tasks)
}

func (pmi *ProjectManagementIntegration) handleAddTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID   string `json:"project_id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Assignee    string `json:"assignee"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	task, err := pmi.AddTask(req.ProjectID, req.Title, req.Description, req.Assignee)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(task)
}

// generateID generates a unique identifier for projects and tasks.
func generateID() string {
	// For simplicity, we use a timestamp. In a real implementation, consider using UUID or other unique ID generators.
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// encryptData encrypts data using Scrypt and AES.
func encryptData(plainText, password string) (string, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(password), salt, n, r, p, keyLength)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	result := append(salt, cipherText...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// decryptData decrypts data using Scrypt and AES.
func decryptData(cipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	salt := data[:saltSize]
	key, err := scrypt.Key([]byte(password), salt, n, r, p, keyLength)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[saltSize:saltSize+nonceSize], data[saltSize+nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
