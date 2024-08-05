package uidesign

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"
)

// LayoutElement represents a single element in the dashboard layout
type LayoutElement struct {
    ID       string `json:"id"`
    Type     string `json:"type"`
    Position struct {
        X int `json:"x"`
        Y int `json:"y"`
    } `json:"position"`
    Size struct {
        Width  int `json:"width"`
        Height int `json:"height"`
    } `json:"size"`
    Data interface{} `json:"data"`
}

// DashboardLayout represents the overall layout of the dashboard
type DashboardLayout struct {
    Elements []LayoutElement `json:"elements"`
    Mutex    sync.RWMutex
}

// InitializeLayout initializes a new dashboard layout
func (d *DashboardLayout) InitializeLayout() {
    d.Elements = []LayoutElement{}
}

// AddElement adds a new element to the dashboard layout
func (d *DashboardLayout) AddElement(element LayoutElement) {
    d.Mutex.Lock()
    defer d.Mutex.Unlock()
    d.Elements = append(d.Elements, element)
}

// UpdateElement updates an existing element in the dashboard layout
func (d *DashboardLayout) UpdateElement(element LayoutElement) error {
    d.Mutex.Lock()
    defer d.Mutex.Unlock()
    for i, el := range d.Elements {
        if el.ID == element.ID {
            d.Elements[i] = element
            return nil
        }
    }
    return fmt.Errorf("element with ID %s not found", element.ID)
}

// DeleteElement removes an element from the dashboard layout
func (d *DashboardLayout) DeleteElement(elementID string) error {
    d.Mutex.Lock()
    defer d.Mutex.Unlock()
    for i, el := range d.Elements {
        if el.ID == elementID {
            d.Elements = append(d.Elements[:i], d.Elements[i+1:]...)
            return nil
        }
    }
    return fmt.Errorf("element with ID %s not found", elementID)
}

// GetLayout returns the current layout of the dashboard
func (d *DashboardLayout) GetLayout() []LayoutElement {
    d.Mutex.RLock()
    defer d.Mutex.RUnlock()
    return d.Elements
}

// ServeHTTP serves the dashboard layout over HTTP
func (d *DashboardLayout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    switch r.Method {
    case http.MethodGet:
        d.Mutex.RLock()
        defer d.Mutex.RUnlock()
        json.NewEncoder(w).Encode(d.Elements)
    case http.MethodPost:
        var element LayoutElement
        if err := json.NewDecoder(r.Body).Decode(&element); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        d.AddElement(element)
        w.WriteHeader(http.StatusCreated)
    case http.MethodPut:
        var element LayoutElement
        if err := json.NewDecoder(r.Body).Decode(&element); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        if err := d.UpdateElement(element); err != nil {
            http.Error(w, err.Error(), http.StatusNotFound)
            return
        }
        w.WriteHeader(http.StatusOK)
    case http.MethodDelete:
        var req struct {
            ID string `json:"id"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        if err := d.DeleteElement(req.ID); err != nil {
            http.Error(w, err.Error(), http.StatusNotFound)
            return
        }
        w.WriteHeader(http.StatusOK)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

// Secure serves the dashboard layout over HTTPS
func (d *DashboardLayout) Secure(certFile, keyFile string) error {
    srv := &http.Server{
        Addr:         ":443",
        Handler:      d,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }
    return srv.ListenAndServeTLS(certFile, keyFile)
}

