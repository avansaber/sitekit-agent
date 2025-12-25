package health

import (
	"fmt"
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
	Name          string  `json:"name"`
	Status        string  `json:"status"` // running, stopped, failed, not-installed
	Enabled       bool    `json:"enabled"`
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryMB      uint64  `json:"memory_mb,omitempty"`
	UptimeSeconds uint64  `json:"uptime_seconds,omitempty"`
}

type DaemonStatus struct {
	Name          string  `json:"name"`
	Status        string  `json:"status"` // RUNNING, STOPPED, STARTING, BACKOFF, STOPPING, EXITED, FATAL, UNKNOWN
	PID           int     `json:"pid,omitempty"`
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryMB      uint64  `json:"memory_mb,omitempty"`
	UptimeSeconds uint64  `json:"uptime_seconds,omitempty"`
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
		"apache2",
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

	// Collect metrics for running services
	if status.Status == "running" {
		collectServiceMetrics(&status, serviceName)
	}

	return status
}

// collectServiceMetrics collects CPU, memory, and uptime for a running service
func collectServiceMetrics(status *ServiceStatus, serviceName string) {
	// Get MainPID and uptime using systemctl show
	showCmd := exec.Command("systemctl", "show", serviceName, "--property=MainPID,ActiveEnterTimestamp,MemoryCurrent,CPUUsageNSec")
	showOutput, err := showCmd.Output()
	if err != nil {
		return
	}

	props := parseSystemctlShow(string(showOutput))

	// Parse MainPID
	pid := props["MainPID"]
	if pid == "" || pid == "0" {
		return
	}

	// Calculate uptime from ActiveEnterTimestamp
	if ts := props["ActiveEnterTimestamp"]; ts != "" {
		status.UptimeSeconds = parseUptimeFromTimestamp(ts)
	}

	// Memory (MemoryCurrent is in bytes, may not be available on all systems)
	if mem := props["MemoryCurrent"]; mem != "" && mem != "[not set]" {
		if memBytes := parseUint64(mem); memBytes > 0 {
			status.MemoryMB = memBytes / 1024 / 1024
		}
	}

	// CPU usage (this is cumulative, not percentage - we'll use it as a rough indicator)
	// For accurate percentage, we'd need to sample over time
	// For now, we'll get per-process CPU from /proc
	if cpuPercent := getProcessCPU(pid); cpuPercent >= 0 {
		status.CPUPercent = cpuPercent
	}
}

func parseSystemctlShow(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func parseUptimeFromTimestamp(ts string) uint64 {
	// Format: "Mon 2024-01-15 10:30:45 UTC"
	// We need to parse this and calculate seconds since then
	cmd := exec.Command("date", "-d", ts, "+%s")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	startTime := parseUint64(strings.TrimSpace(string(output)))

	nowCmd := exec.Command("date", "+%s")
	nowOutput, err := nowCmd.Output()
	if err != nil {
		return 0
	}
	nowTime := parseUint64(strings.TrimSpace(string(nowOutput)))

	if nowTime > startTime {
		return nowTime - startTime
	}
	return 0
}

func parseUint64(s string) uint64 {
	var val uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			val = val*10 + uint64(c-'0')
		} else {
			break
		}
	}
	return val
}

func getProcessCPU(pid string) float64 {
	// Use ps to get CPU percentage
	cmd := exec.Command("ps", "-p", pid, "-o", "%cpu", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return -1
	}

	cpuStr := strings.TrimSpace(string(output))
	if cpuStr == "" {
		return 0
	}

	// Parse float
	var cpu float64
	for i, c := range cpuStr {
		if c == '.' {
			// Parse decimal part
			var decimal float64
			var factor float64 = 0.1
			for _, d := range cpuStr[i+1:] {
				if d >= '0' && d <= '9' {
					decimal += float64(d-'0') * factor
					factor /= 10
				} else {
					break
				}
			}
			cpu += decimal
			break
		} else if c >= '0' && c <= '9' {
			cpu = cpu*10 + float64(c-'0')
		}
	}

	return cpu
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

// CollectDaemonStatuses collects status for all supervisor-managed programs
func CollectDaemonStatuses() []DaemonStatus {
	var daemons []DaemonStatus

	// Run supervisorctl status to get all programs
	cmd := exec.Command("supervisorctl", "status")
	output, err := cmd.Output()
	if err != nil {
		// Supervisor might not be running or installed
		return daemons
	}

	// Parse output lines
	// Format: program_name                    STATUS     pid PID, uptime H:MM:SS
	// Example: laravel-worker:laravel-worker_00   RUNNING    pid 12345, uptime 1:23:45
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		daemon := parseSupervisorStatusLine(line)
		if daemon.Name != "" {
			// Collect metrics for running daemons
			if daemon.Status == "RUNNING" && daemon.PID > 0 {
				collectDaemonMetrics(&daemon)
			}
			daemons = append(daemons, daemon)
		}
	}

	return daemons
}

func parseSupervisorStatusLine(line string) DaemonStatus {
	daemon := DaemonStatus{}

	// Split by whitespace
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return daemon
	}

	daemon.Name = fields[0]
	daemon.Status = fields[1]

	// Parse PID if present (format: "pid 12345,")
	for i, field := range fields {
		if field == "pid" && i+1 < len(fields) {
			pidStr := strings.TrimSuffix(fields[i+1], ",")
			daemon.PID = int(parseUint64(pidStr))
		}
		if field == "uptime" && i+1 < len(fields) {
			daemon.UptimeSeconds = parseUptimeString(fields[i+1])
		}
	}

	return daemon
}

func parseUptimeString(uptime string) uint64 {
	// Format: H:MM:SS or D days, H:MM:SS
	var total uint64

	// Check for days
	if strings.Contains(uptime, "days,") {
		parts := strings.SplitN(uptime, "days,", 2)
		days := parseUint64(strings.TrimSpace(parts[0]))
		total += days * 24 * 3600
		if len(parts) > 1 {
			uptime = strings.TrimSpace(parts[1])
		}
	} else if strings.Contains(uptime, "day,") {
		parts := strings.SplitN(uptime, "day,", 2)
		days := parseUint64(strings.TrimSpace(parts[0]))
		total += days * 24 * 3600
		if len(parts) > 1 {
			uptime = strings.TrimSpace(parts[1])
		}
	}

	// Parse H:MM:SS
	timeParts := strings.Split(uptime, ":")
	if len(timeParts) == 3 {
		hours := parseUint64(timeParts[0])
		mins := parseUint64(timeParts[1])
		secs := parseUint64(timeParts[2])
		total += hours*3600 + mins*60 + secs
	}

	return total
}

func collectDaemonMetrics(daemon *DaemonStatus) {
	if daemon.PID <= 0 {
		return
	}

	pidStr := fmt.Sprintf("%d", daemon.PID)

	// Get CPU percentage
	if cpu := getProcessCPU(pidStr); cpu >= 0 {
		daemon.CPUPercent = cpu
	}

	// Get memory usage from /proc/PID/status
	statusPath := fmt.Sprintf("/proc/%d/status", daemon.PID)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			// Format: VmRSS:     12345 kB
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kbytes := parseUint64(fields[1])
				daemon.MemoryMB = kbytes / 1024
			}
			break
		}
	}
}

