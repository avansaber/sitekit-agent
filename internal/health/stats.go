package health

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

type SystemStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	CPUCount      int     `json:"cpu_count"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryUsedMB  uint64  `json:"memory_used_mb"`
	MemoryTotalMB uint64  `json:"memory_total_mb"`
	DiskPercent   float64 `json:"disk_percent"`
	DiskUsedGB    uint64  `json:"disk_used_gb"`
	DiskTotalGB   uint64  `json:"disk_total_gb"`
	LoadAvg1      float64 `json:"load_avg_1"`
	LoadAvg5      float64 `json:"load_avg_5"`
	LoadAvg15     float64 `json:"load_avg_15"`
	OSName        string  `json:"os_name"`
	OSVersion     string  `json:"os_version"`
}

type ServiceStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // running, stopped, failed, not-installed
	Enabled bool   `json:"enabled"`
}

func CollectStats() (*SystemStats, error) {
	stats := &SystemStats{
		CPUCount: runtime.NumCPU(),
	}

	// CPU percent
	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		stats.CPUPercent = cpuPercent[0]
	}

	// Memory
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		stats.MemoryPercent = memInfo.UsedPercent
		stats.MemoryUsedMB = memInfo.Used / 1024 / 1024
		stats.MemoryTotalMB = memInfo.Total / 1024 / 1024
	}

	// Disk
	diskInfo, err := disk.Usage("/")
	if err == nil {
		stats.DiskPercent = diskInfo.UsedPercent
		stats.DiskUsedGB = diskInfo.Used / 1024 / 1024 / 1024
		stats.DiskTotalGB = diskInfo.Total / 1024 / 1024 / 1024
	}

	// Load average
	loadInfo, err := load.Avg()
	if err == nil {
		stats.LoadAvg1 = loadInfo.Load1
		stats.LoadAvg5 = loadInfo.Load5
		stats.LoadAvg15 = loadInfo.Load15
	}

	// OS info
	hostInfo, err := host.Info()
	if err == nil {
		stats.OSName = hostInfo.Platform
		stats.OSVersion = hostInfo.PlatformVersion
	}

	return stats, nil
}

func CollectServiceStatuses() []ServiceStatus {
	services := []string{
		"nginx",
		"mysql",
		"mariadb",
		"redis-server",
		"supervisor",
		"php8.3-fpm",
		"php8.2-fpm",
		"php8.1-fpm",
		"php8.0-fpm",
		"php7.4-fpm",
		"postgresql",
	}

	var statuses []ServiceStatus

	for _, svc := range services {
		status := checkServiceStatus(svc)
		if status.Status != "not-installed" {
			statuses = append(statuses, status)
		}
	}

	return statuses
}

func checkServiceStatus(serviceName string) ServiceStatus {
	status := ServiceStatus{Name: serviceName}

	// Check if service unit exists
	checkCmd := exec.Command("systemctl", "list-unit-files", serviceName+".service")
	output, err := checkCmd.Output()
	if err != nil || !strings.Contains(string(output), serviceName) {
		status.Status = "not-installed"
		return status
	}

	// Check if active
	activeCmd := exec.Command("systemctl", "is-active", serviceName)
	activeOutput, _ := activeCmd.Output()
	activeStatus := strings.TrimSpace(string(activeOutput))

	switch activeStatus {
	case "active":
		status.Status = "running"
	case "failed":
		status.Status = "failed"
	default:
		status.Status = "stopped"
	}

	// Check if enabled
	enabledCmd := exec.Command("systemctl", "is-enabled", serviceName)
	enabledOutput, _ := enabledCmd.Output()
	status.Enabled = strings.TrimSpace(string(enabledOutput)) == "enabled"

	return status
}

func GetMachineID() string {
	// Try Linux machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Fallback to hostname
	hostname, _ := os.Hostname()
	return hostname
}
