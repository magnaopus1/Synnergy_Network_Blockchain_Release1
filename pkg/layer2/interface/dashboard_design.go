package user_interface

import (
    "github.com/gotk3/gotk3/gtk"
    "log"
    "os"
)

// Constants for UI design
const (
    WindowWidth  = 800
    WindowHeight = 600
)

// DashboardUI holds the elements of the dashboard interface
type DashboardUI struct {
    Window   *gtk.Window
    Grid     *gtk.Grid
    InfoLabel *gtk.Label
}

// NewDashboardUI creates a new UI instance
func NewDashboardUI() *DashboardUI {
    gtk.Init(nil)

    // Create new top-level window.
    win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
    if err != nil {
        log.Fatal("Unable to create window:", err)
        os.Exit(1)
    }
    win.SetTitle("Synthron Blockchain Dashboard")
    win.Connect("destroy", func() {
        gtk.MainQuit()
    })
    win.SetDefaultSize(WindowWidth, WindowHeight)

    // Create Grid
    grid, err := gtk.GridNew()
    if err != nil {
        log.Fatal("Unable to create grid:", err)
        os.Exit(1)
    }
    win.Add(grid)

    // Create InfoLabel
    label, err := gtk.LabelNew("Blockchain Status: Initializing...")
    if err != nil {
        log.Fatal("Unable to create label:", err)
        os.Exit(1)
    }
    grid.Attach(label, 0, 0, 1, 1)

    return &DashboardUI{
        Window:   win,
        Grid:     grid,
        InfoLabel: label,
    }
}

// UpdateInfo updates the information displayed on the dashboard
func (ui *DashboardUI) UpdateInfo(info string) {
    glib.IdleAdd(func() {
        ui.InfoLabel.SetText(info)
    })
}

// Display renders the UI
func (ui *DashboardUI) Display() {
    ui.Window.ShowAll()
    gtk.Main()
}

// main function to run the dashboard
func main() {
    ui := NewDashboardUI()
    ui.UpdateInfo("Blockchain Operational")
    ui.Display()
}
