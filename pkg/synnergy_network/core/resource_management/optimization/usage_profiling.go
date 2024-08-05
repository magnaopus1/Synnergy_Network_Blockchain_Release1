package optimization

import (
    "runtime"
    "runtime/pprof"
    "time"
    "sync"
    "os"
    "fmt"
    "log"
    "encoding/json"
)

// Define the Profiling struct
type Profiling struct {
    CPUProfile        *os.File
    MemProfile        *os.File
    MutexProfile      *os.File
    BlockProfile      *os.File
    GoroutineProfile  *os.File
    ProfileDuration   time.Duration
    OutputDirectory   string
    Mutex             sync.Mutex
}

// InitializeProfiling initializes profiling with default settings.
func InitializeProfiling(duration time.Duration, outputDir string) (*Profiling, error) {
    p := &Profiling{
        ProfileDuration: duration,
        OutputDirectory: outputDir,
    }

    err := os.MkdirAll(outputDir, os.ModePerm)
    if err != nil {
        return nil, fmt.Errorf("failed to create output directory: %v", err)
    }

    return p, nil
}

// StartCPUProfile starts CPU profiling.
func (p *Profiling) StartCPUProfile() error {
    p.Mutex.Lock()
    defer p.Mutex.Unlock()

    var err error
    p.CPUProfile, err = os.Create(fmt.Sprintf("%s/cpu_profile.prof", p.OutputDirectory))
    if err != nil {
        return fmt.Errorf("could not create CPU profile: %v", err)
    }
    return pprof.StartCPUProfile(p.CPUProfile)
}

// StopCPUProfile stops the CPU profiling and closes the file.
func (p *Profiling) StopCPUProfile() {
    p.Mutex.Lock()
    defer p.Mutex.Unlock()

    pprof.StopCPUProfile()
    if p.CPUProfile != nil {
        p.CPUProfile.Close()
        p.CPUProfile = nil
    }
}

// SaveMemoryProfile saves a memory profile.
func (p *Profiling) SaveMemoryProfile() error {
    p.Mutex.Lock()
    defer p.Mutex.Unlock()

    p.MemProfile, err := os.Create(fmt.Sprintf("%s/memory_profile.prof", p.OutputDirectory))
    if err != nil {
        return fmt.Errorf("could not create memory profile: %v", err)
    }
    defer p.MemProfile.Close()

    return pprof.WriteHeapProfile(p.MemProfile)
}

// MonitorUsage continuously monitors and logs resource usage.
func (p *Profiling) MonitorUsage(interval time.Duration) {
    for {
        select {
        case <-time.After(interval):
            p.logResourceUsage()
        }
    }
}

// logResourceUsage logs current memory and goroutine usage.
func (p *Profiling) logResourceUsage() {
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)
    log.Printf("Alloc = %v MiB", bToMb(memStats.Alloc))
    log.Printf("TotalAlloc = %v MiB", bToMb(memStats.TotalAlloc))
    log.Printf("Sys = %v MiB", bToMb(memStats.Sys))
    log.Printf("NumGC = %v\n", memStats.NumGC)
    log.Printf("NumGoroutine = %v\n", runtime.NumGoroutine())
}

// bToMb converts bytes to megabytes.
func bToMb(b uint64) uint64 {
    return b / 1024 / 1024
}

// SaveProfiles saves all collected profiles to the output directory.
func (p *Profiling) SaveProfiles() error {
    p.StopCPUProfile()
    if err := p.SaveMemoryProfile(); err != nil {
        return err
    }
    return nil
}

// SerializeProfilingData serializes profiling data to JSON.
func (p *Profiling) SerializeProfilingData(filename string) error {
    data := map[string]interface{}{
        "CPUProfile":       p.CPUProfile.Name(),
        "MemProfile":       p.MemProfile.Name(),
        "MutexProfile":     p.MutexProfile.Name(),
        "BlockProfile":     p.BlockProfile.Name(),
        "GoroutineProfile": p.GoroutineProfile.Name(),
        "Duration":         p.ProfileDuration.String(),
    }

    file, err := os.Create(filename)
    if err != nil {
        return fmt.Errorf("could not create JSON file: %v", err)
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    return encoder.Encode(data)
}

// StartProfilingSession starts a full profiling session.
func (p *Profiling) StartProfilingSession() error {
    if err := p.StartCPUProfile(); err != nil {
        return err
    }
    log.Printf("Started CPU profiling for %v", p.ProfileDuration)

    time.Sleep(p.ProfileDuration)

    if err := p.SaveProfiles(); err != nil {
        return err
    }

    log.Printf("Profiling session completed. Profiles saved to %s", p.OutputDirectory)
    return nil
}
