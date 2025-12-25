package executor

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/avansaber/sitekit-agent/internal/comm"
)

// testDatabaseConfig returns empty database configs for testing
func testDatabaseConfig() (DatabaseConfig, DatabaseConfig) {
	return DatabaseConfig{}, DatabaseConfig{}
}

func TestExecutorRegisterAndExecute(t *testing.T) {
	mysqlCfg, pgCfg := testDatabaseConfig()
	exec := NewExecutor(5*time.Second, mysqlCfg, pgCfg)

	// Register a test handler
	exec.Register("test_job", func(ctx context.Context, payload json.RawMessage) comm.JobResult {
		var p struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return comm.JobResult{Success: false, Error: err.Error()}
		}
		return comm.JobResult{Success: true, Output: "Received: " + p.Message}
	})

	// Execute the job
	payload := json.RawMessage(`{"message": "Hello"}`)
	result := exec.Execute(context.Background(), "test_job", payload)

	if !result.Success {
		t.Errorf("Job should have succeeded: %v", result.Error)
	}

	if result.Output != "Received: Hello" {
		t.Errorf("Unexpected output: %s", result.Output)
	}
}

func TestExecutorUnknownJob(t *testing.T) {
	mysqlCfg, pgCfg := testDatabaseConfig()
	exec := NewExecutor(5*time.Second, mysqlCfg, pgCfg)

	result := exec.Execute(context.Background(), "unknown_job", nil)

	if result.Success {
		t.Error("Job should have failed for unknown type")
	}

	if result.Error != "unknown job type: unknown_job" {
		t.Errorf("Unexpected error: %s", result.Error)
	}
}

func TestExecutorRunCommand(t *testing.T) {
	mysqlCfg, pgCfg := testDatabaseConfig()
	exec := NewExecutor(5*time.Second, mysqlCfg, pgCfg)

	output, err := exec.RunCommand(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	if output != "hello\n" {
		t.Errorf("Unexpected output: %q", output)
	}
}

func TestExecutorRunCommandTimeout(t *testing.T) {
	mysqlCfg, pgCfg := testDatabaseConfig()
	exec := NewExecutor(100*time.Millisecond, mysqlCfg, pgCfg)

	_, err := exec.RunCommand(context.Background(), "sleep", "10")
	if err != ErrTimeout {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestExecutorRunCommandWithExitCode(t *testing.T) {
	mysqlCfg, pgCfg := testDatabaseConfig()
	exec := NewExecutor(5*time.Second, mysqlCfg, pgCfg)

	// Success case
	output, exitCode, err := exec.RunCommandWithExitCode(context.Background(), "true")
	if err != nil {
		t.Errorf("Command should succeed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Exit code should be 0, got %d", exitCode)
	}

	// Failure case
	output, exitCode, err = exec.RunCommandWithExitCode(context.Background(), "false")
	if err == nil {
		t.Error("Command should fail")
	}
	if exitCode != 1 {
		t.Errorf("Exit code should be 1, got %d (output: %s)", exitCode, output)
	}
}

func TestGetSystemdServiceName(t *testing.T) {
	tests := []struct {
		serviceType string
		version     string
		expected    string
	}{
		{"php", "8.3", "php8.3-fpm"},
		{"php", "8.2", "php8.2-fpm"},
		{"mysql", "", "mysql"},
		{"mariadb", "", "mariadb"},
		{"postgresql", "", "postgresql"},
		{"redis", "", "redis-server"},
		{"memcached", "", "memcached"},
		{"nginx", "", "nginx"},
		{"supervisor", "", "supervisor"},
		{"nodejs", "", "node"},
		{"custom", "", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.serviceType+"-"+tt.version, func(t *testing.T) {
			result := getSystemdServiceName(tt.serviceType, tt.version)
			if result != tt.expected {
				t.Errorf("getSystemdServiceName(%s, %s) = %s, want %s",
					tt.serviceType, tt.version, result, tt.expected)
			}
		})
	}
}

func TestGetInstallCommands(t *testing.T) {
	// Test PHP installation commands
	commands := getInstallCommands("php", "8.3", nil)
	if len(commands) == 0 {
		t.Error("Expected install commands for PHP")
	}

	// Test Node.js installation commands
	commands = getInstallCommands("nodejs", "20", nil)
	if len(commands) == 0 {
		t.Error("Expected install commands for Node.js")
	}

	// Test unknown service
	commands = getInstallCommands("unknown", "", nil)
	if len(commands) != 0 {
		t.Error("Expected no commands for unknown service")
	}
}

func TestErrToString(t *testing.T) {
	if errToString(nil) != "" {
		t.Error("errToString(nil) should return empty string")
	}

	err := context.DeadlineExceeded
	if errToString(err) != err.Error() {
		t.Error("errToString should return error string")
	}
}

func TestExecutorRegisterHandlers(t *testing.T) {
	mysqlCfg, pgCfg := testDatabaseConfig()
	exec := NewExecutor(5*time.Second, mysqlCfg, pgCfg)
	exec.RegisterHandlers()

	// Check that handlers are registered
	expectedHandlers := []string{
		// Service management
		"service_restart", "service_start", "service_stop", "service_reload",
		"service_install", "service_uninstall",
		// User management
		"create_user", "delete_user",
		// SSH keys
		"ssh_key_add", "ssh_key_remove", "ssh_key_sync",
		// Firewall
		"firewall_apply", "firewall_revert",
		"enable_firewall", "apply_firewall_rule", "revert_firewall_rule",
		// Web apps
		"create_webapp", "update_webapp_config", "delete_webapp",
		// SSL
		"ssl_issue", "ssl_renew", "ssl_install",
		// Databases
		"create_database", "delete_database",
		"create_database_user", "delete_database_user",
		"export_database", "import_database", "optimize_database",
		// Environment
		"update_env_file",
		// Crontab
		"sync_crontab",
		// Deployment
		"deploy", "rollback_deployment", "cleanup_releases",
		// Generic
		"run_script",
	}

	for _, handler := range expectedHandlers {
		if _, ok := exec.handlers[handler]; !ok {
			t.Errorf("Handler %s not registered", handler)
		}
	}
}
