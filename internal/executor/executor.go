package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/avansaber/sitekit-agent/internal/comm"
	"github.com/rs/zerolog/log"
)

var ErrTimeout = errors.New("command timed out")

type JobHandler func(ctx context.Context, payload json.RawMessage) comm.JobResult

// DatabaseConfig holds database connection credentials
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
}

type Executor struct {
	defaultTimeout time.Duration
	handlers       map[string]JobHandler
	mysqlConfig    DatabaseConfig
	postgresConfig DatabaseConfig
}

func NewExecutor(timeout time.Duration, mysqlCfg, postgresCfg DatabaseConfig) *Executor {
	return &Executor{
		defaultTimeout: timeout,
		handlers:       make(map[string]JobHandler),
		mysqlConfig:    mysqlCfg,
		postgresConfig: postgresCfg,
	}
}

func (e *Executor) Register(jobType string, handler JobHandler) {
	e.handlers[jobType] = handler
}

func (e *Executor) Execute(ctx context.Context, jobType string, payload json.RawMessage) comm.JobResult {
	handler, ok := e.handlers[jobType]
	if !ok {
		return comm.JobResult{
			Success: false,
			Error:   fmt.Sprintf("unknown job type: %s", jobType),
		}
	}

	return handler(ctx, payload)
}

// RunCommand executes a command with timeout and proper process group handling
func (e *Executor) RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, e.defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	// Set process group so we can kill all children
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n" + stderr.String()
	}

	if ctx.Err() == context.DeadlineExceeded {
		// Kill entire process group
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return output, ErrTimeout
	}

	return output, err
}

// RunCommandWithExitCode runs a command and returns the exit code
func (e *Executor) RunCommandWithExitCode(ctx context.Context, name string, args ...string) (string, int, error) {
	output, err := e.RunCommand(ctx, name, args...)

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return output, exitCode, err
}

func (e *Executor) RegisterHandlers() {
	// Service management
	e.Register("service_restart", e.handleServiceRestart)
	e.Register("service_start", e.handleServiceStart)
	e.Register("service_stop", e.handleServiceStop)
	e.Register("service_reload", e.handleServiceReload)
	e.Register("service_install", e.handleServiceInstall)
	e.Register("service_uninstall", e.handleServiceUninstall)

	// PHP extension management
	e.Register("php_install_extension", e.handlePhpInstallExtension)
	e.Register("php_uninstall_extension", e.handlePhpUninstallExtension)

	// Config validation
	e.Register("validate_nginx_config", e.handleValidateNginxConfig)
	e.Register("validate_php_config", e.handleValidatePhpConfig)

	// User management
	e.Register("create_user", e.handleCreateUser)
	e.Register("delete_user", e.handleDeleteUser)

	// SSH key management
	e.Register("ssh_key_add", e.handleSSHKeyAdd)
	e.Register("ssh_key_remove", e.handleSSHKeyRemove)
	e.Register("ssh_key_sync", e.handleSSHKeySync)

	// Firewall
	e.Register("firewall_apply", e.handleFirewallApply)
	e.Register("firewall_revert", e.handleFirewallRevert)
	e.Register("enable_firewall", e.handleEnableFirewall)
	e.Register("apply_firewall_rule", e.handleApplyFirewallRule)
	e.Register("revert_firewall_rule", e.handleRevertFirewallRule)

	// Web Applications
	e.Register("create_webapp", e.handleCreateWebApp)
	e.Register("update_webapp_config", e.handleUpdateWebAppConfig)
	e.Register("delete_webapp", e.handleDeleteWebApp)

	// SSL Certificates
	e.Register("ssl_issue", e.handleIssueSSL)
	e.Register("ssl_renew", e.handleRenewSSL)
	e.Register("ssl_install", e.handleInstallSSL)

	// System maintenance
	e.Register("fix_permissions", e.handleFixPermissions)

	// Databases
	e.Register("create_database", e.handleCreateDatabase)
	e.Register("delete_database", e.handleDeleteDatabase)
	e.Register("create_database_user", e.handleCreateDatabaseUser)
	e.Register("delete_database_user", e.handleDeleteDatabaseUser)
	e.Register("export_database", e.handleExportDatabase)
	e.Register("import_database", e.handleImportDatabase)
	e.Register("optimize_database", e.handleOptimizeDatabase)
	e.Register("database_backup", e.handleDatabaseBackup)

	// Environment
	e.Register("update_env_file", e.handleUpdateEnvFile)

	// Crontab
	e.Register("sync_crontab", e.handleSyncCrontab)

	// Deployment
	e.Register("deploy", e.handleDeploy)
	e.Register("git_deploy", e.handleDeploy) // Alias for deploy
	e.Register("rollback_deployment", e.handleRollbackDeployment)
	e.Register("cleanup_releases", e.handleCleanupReleases)

	// Supervisor
	e.Register("supervisor_create", e.handleSupervisorCreate)
	e.Register("supervisor_update", e.handleSupervisorUpdate)
	e.Register("supervisor_delete", e.handleSupervisorDelete)
	e.Register("supervisor_start", e.handleSupervisorStart)
	e.Register("supervisor_stop", e.handleSupervisorStop)
	e.Register("supervisor_restart", e.handleSupervisorRestart)

	// Apache (for nginx_apache hybrid mode)
	e.Register("create_apache_vhost", e.handleCreateApacheVhost)
	e.Register("update_apache_vhost", e.handleUpdateApacheVhost)
	e.Register("delete_apache_vhost", e.handleDeleteApacheVhost)

	// File Manager
	e.Register("list_directory", e.handleListDirectory)
	e.Register("read_file", e.handleReadFile)
	e.Register("write_file", e.handleWriteFile)
	e.Register("delete_file", e.handleDeleteFile)
	e.Register("create_directory", e.handleCreateDirectory)
	e.Register("rename_file", e.handleRenameFile)
	e.Register("get_file_info", e.handleGetFileInfo)
	e.Register("chmod_file", e.handleChmodFile)

	// Log Viewer
	e.Register("list_logs", e.handleListLogs)
	e.Register("tail_log", e.handleTailLog)
	e.Register("search_log", e.handleSearchLog)
	e.Register("clear_log", e.handleClearLog)
	e.Register("download_log", e.handleDownloadLog)

	// Generic command (use with caution)
	e.Register("run_script", e.handleRunScript)

	// Health monitoring
	e.Register("check_services", e.handleCheckServices)

	// Server management
	e.Register("server_restore", e.handleServerRestore)

	// Provisioning (software installation)
	e.Register("provision_system", e.handleProvisionSystem)
	e.Register("provision_nginx", e.handleProvisionNginx)
	e.Register("provision_apache", e.handleProvisionApache)
	e.Register("provision_php", e.handleProvisionPHP)
	e.Register("provision_mariadb", e.handleProvisionMariaDB)
	e.Register("provision_mysql", e.handleProvisionMySQL)
	e.Register("provision_postgresql", e.handleProvisionPostgreSQL)
	e.Register("provision_redis", e.handleProvisionRedis)
	e.Register("provision_memcached", e.handleProvisionMemcached)
	e.Register("provision_composer", e.handleProvisionComposer)
	e.Register("provision_node", e.handleProvisionNode)
	e.Register("provision_supervisor", e.handleProvisionSupervisor)

	log.Info().Int("handlers", len(e.handlers)).Msg("Registered job handlers")
}
