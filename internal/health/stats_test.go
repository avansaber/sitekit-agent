package health

import (
	"runtime"
	"testing"
)

func TestCollectStats(t *testing.T) {
	stats, err := CollectStats()
	if err != nil {
		t.Fatalf("CollectStats failed: %v", err)
	}

	// CPU count should match runtime
	if stats.CPUCount != runtime.NumCPU() {
		t.Errorf("CPUCount = %d, want %d", stats.CPUCount, runtime.NumCPU())
	}

	// CPU percent should be in valid range
	if stats.CPUPercent < 0 || stats.CPUPercent > 100 {
		t.Errorf("CPUPercent = %f, should be 0-100", stats.CPUPercent)
	}

	// Memory percent should be in valid range
	if stats.MemoryPercent < 0 || stats.MemoryPercent > 100 {
		t.Errorf("MemoryPercent = %f, should be 0-100", stats.MemoryPercent)
	}

	// Total memory should be greater than 0
	if stats.MemoryTotalMB == 0 {
		t.Error("MemoryTotalMB should be > 0")
	}

	// Used memory should not exceed total
	if stats.MemoryUsedMB > stats.MemoryTotalMB {
		t.Errorf("MemoryUsedMB (%d) > MemoryTotalMB (%d)", stats.MemoryUsedMB, stats.MemoryTotalMB)
	}

	// Disk percent should be in valid range
	if stats.DiskPercent < 0 || stats.DiskPercent > 100 {
		t.Errorf("DiskPercent = %f, should be 0-100", stats.DiskPercent)
	}

	// Load average should be non-negative (only on Unix)
	if runtime.GOOS != "windows" {
		if stats.LoadAvg1 < 0 || stats.LoadAvg5 < 0 || stats.LoadAvg15 < 0 {
			t.Error("Load averages should be non-negative")
		}
	}
}

func TestGetMachineID(t *testing.T) {
	machineID := GetMachineID()
	if machineID == "" {
		t.Error("GetMachineID should return a non-empty string")
	}
}

func TestSystemStatsFields(t *testing.T) {
	stats := &SystemStats{
		CPUPercent:    45.5,
		CPUCount:      8,
		MemoryPercent: 60.0,
		MemoryUsedMB:  8192,
		MemoryTotalMB: 16384,
		DiskPercent:   75.0,
		DiskUsedGB:    300,
		DiskTotalGB:   400,
		LoadAvg1:      1.5,
		LoadAvg5:      2.0,
		LoadAvg15:     2.5,
		OSName:        "ubuntu",
		OSVersion:     "22.04",
	}

	if stats.CPUPercent != 45.5 {
		t.Error("CPUPercent not set correctly")
	}
	if stats.OSName != "ubuntu" {
		t.Error("OSName not set correctly")
	}
}

func TestServiceStatus(t *testing.T) {
	status := ServiceStatus{
		Name:    "nginx",
		Status:  "running",
		Enabled: true,
	}

	if status.Name != "nginx" {
		t.Error("Name not set correctly")
	}
	if status.Status != "running" {
		t.Error("Status not set correctly")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
}
