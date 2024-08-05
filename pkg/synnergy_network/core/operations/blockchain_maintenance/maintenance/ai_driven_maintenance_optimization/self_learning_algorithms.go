package ai_driven_maintenance_optimization

import (
    "log"
    "math/rand"
    "sync"
    "time"

    "github.com/synnergy_network/pkg/synnergy_network/core/operations/utils/encryption_utils"
    "github.com/synnergy_network/pkg/synnergy_network/core/operations/utils/logging_utils"
    "github.com/synnergy_network/pkg/synnergy_network/core/operations/utils/monitoring_utils"
)

type ResourceAllocationOptimization struct {
    resources          map[string]int
    usageData          map[string][]int
    optimizationMutex  sync.Mutex
    encryptionUtil     encryption_utils.EncryptionUtil
    logger             logging_utils.Logger
    monitoringUtil     monitoring_utils.MonitoringUtil
}

func NewResourceAllocationOptimization() *ResourceAllocationOptimization {
    return &ResourceAllocationOptimization{
        resources:      make(map[string]int),
        usageData:      make(map[string][]int),
        encryptionUtil: encryption_utils.NewEncryptionUtil(),
        logger:         logging_utils.NewLogger(),
        monitoringUtil: monitoring_utils.NewMonitoringUtil(),
    }
}

func (rao *ResourceAllocationOptimization) AddResource(resourceID string, capacity int) {
    rao.optimizationMutex.Lock()
    defer rao.optimizationMutex.Unlock()

    rao.resources[resourceID] = capacity
    rao.logger.LogInfo("Added resource: " + resourceID)
}

func (rao *ResourceAllocationOptimization) RemoveResource(resourceID string) {
    rao.optimizationMutex.Lock()
    defer rao.optimizationMutex.Unlock()

    delete(rao.resources, resourceID)
    rao.logger.LogInfo("Removed resource: " + resourceID)
}

func (rao *ResourceAllocationOptimization) RecordUsage(resourceID string, usage int) {
    rao.optimizationMutex.Lock()
    defer rao.optimizationMutex.Unlock()

    rao.usageData[resourceID] = append(rao.usageData[resourceID], usage)
    rao.logger.LogInfo("Recorded usage for resource: " + resourceID)
}

func (rao *ResourceAllocationOptimization) OptimizeResourceAllocation() {
    rao.optimizationMutex.Lock()
    defer rao.optimizationMutex.Unlock()

    // Simulating resource allocation optimization using AI/ML
    for resourceID, usageHistory := range rao.usageData {
        optimalAllocation := rao.calculateOptimalAllocation(usageHistory)
        rao.resources[resourceID] = optimalAllocation
        rao.logger.LogInfo("Optimized allocation for resource: " + resourceID)
    }
}

func (rao *ResourceAllocationOptimization) calculateOptimalAllocation(usageHistory []int) int {
    if len(usageHistory) == 0 {
        return rand.Intn(100)
    }

    totalUsage := 0
    for _, usage := range usageHistory {
        totalUsage += usage
    }

    averageUsage := totalUsage / len(usageHistory)
    return averageUsage + rand.Intn(10)
}

func (rao *ResourceAllocationOptimization) SecureData() {
    rao.optimizationMutex.Lock()
    defer rao.optimizationMutex.Unlock()

    encryptedData, err := rao.encryptionUtil.EncryptData(rao.usageData)
    if err != nil {
        rao.logger.LogError("Error encrypting data: " + err.Error())
        return
    }

    rao.logger.LogInfo("Data encrypted successfully")
    _ = encryptedData
}

func (rao *ResourceAllocationOptimization) MonitorResourceUsage() {
    for {
        time.Sleep(5 * time.Second)

        rao.optimizationMutex.Lock()
        for resourceID, capacity := range rao.resources {
            currentUsage := rao.monitoringUtil.GetResourceUsage(resourceID)
            usagePercentage := (currentUsage * 100) / capacity
            rao.logger.LogInfo("Resource " + resourceID + " usage: " + string(usagePercentage) + "%")

            if usagePercentage > 80 {
                rao.logger.LogWarning("Resource " + resourceID + " is over 80% usage")
            }
        }
        rao.optimizationMutex.Unlock()
    }
}
