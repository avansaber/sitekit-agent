package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hostman/hostman-agent/internal/comm"
	"github.com/rs/zerolog/log"
)

// Service handlers

func (e *Executor) handleServiceRestart(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceType string `json:"service_type"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	serviceName := getSystemdServiceName(p.ServiceType, p.Version)
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "systemctl", "restart", serviceName)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleServiceStart(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceType string `json:"service_type"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	serviceName := getSystemdServiceName(p.ServiceType, p.Version)
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "systemctl", "start", serviceName)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleServiceStop(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceType string `json:"service_type"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	serviceName := getSystemdServiceName(p.ServiceType, p.Version)
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "systemctl", "stop", serviceName)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleServiceReload(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceType string `json:"service_type"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	serviceName := getSystemdServiceName(p.ServiceType, p.Version)
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "systemctl", "reload", serviceName)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleServiceInstall(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceID   string   `json:"service_id"`
		ServiceType string   `json:"service_type"`
		Version     string   `json:"version"`
		IsDefault   bool     `json:"is_default"`
		Extensions  []string `json:"extensions,omitempty"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("service", p.ServiceType).
		Str("version", p.Version).
		Msg("Installing service")

	var output strings.Builder
	var lastErr error

	// Run install commands based on service type
	commands := getInstallCommands(p.ServiceType, p.Version, p.Extensions)
	for _, cmd := range commands {
		log.Debug().Str("cmd", strings.Join(cmd, " ")).Msg("Running install command")
		out, _, err := e.RunCommandWithExitCode(ctx, cmd[0], cmd[1:]...)
		output.WriteString(out + "\n")
		if err != nil {
			lastErr = err
			output.WriteString(fmt.Sprintf("Error: %v\n", err))
			break
		}
	}

	return comm.JobResult{
		Success: lastErr == nil,
		Output:  output.String(),
		Error:   errToString(lastErr),
	}
}

func (e *Executor) handleServiceUninstall(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceID   string `json:"service_id"`
		ServiceType string `json:"service_type"`
		Version     string `json:"version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Stop the service first
	serviceName := getSystemdServiceName(p.ServiceType, p.Version)
	e.RunCommand(ctx, "systemctl", "stop", serviceName)
	e.RunCommand(ctx, "systemctl", "disable", serviceName)

	// Note: We don't actually uninstall packages to avoid breaking other things
	// Just stop and disable the service

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Service %s stopped and disabled", serviceName),
	}
}

// User handlers

func (e *Executor) handleCreateUser(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Username string `json:"username"`
		HomeDir  string `json:"home_dir"`
		AppID    string `json:"app_id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Validate username format
	if !regexp.MustCompile(`^hm_[a-z0-9]+$`).MatchString(p.Username) {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("invalid username format: %s", p.Username)}
	}

	// Check if user already exists
	if _, err := user.Lookup(p.Username); err == nil {
		return comm.JobResult{Success: true, Output: "User already exists"}
	}

	// Create user
	output, exitCode, err := e.RunCommandWithExitCode(ctx,
		"useradd", "-m", "-d", p.HomeDir, "-s", "/bin/bash", "-G", "www-data", p.Username)
	if err != nil {
		return comm.JobResult{Success: false, Output: output, Error: err.Error(), ExitCode: exitCode}
	}

	// Create standard directories
	dirs := []string{"logs", "tmp", ".ssh"}
	for _, dir := range dirs {
		os.MkdirAll(filepath.Join(p.HomeDir, dir), 0755)
	}

	// Set ownership
	e.RunCommand(ctx, "chown", "-R", p.Username+":"+p.Username, p.HomeDir)

	// Secure .ssh
	os.Chmod(filepath.Join(p.HomeDir, ".ssh"), 0700)

	return comm.JobResult{Success: true, Output: output}
}

func (e *Executor) handleDeleteUser(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Username    string `json:"username"`
		DeleteFiles bool   `json:"delete_files"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Check if user exists
	if _, err := user.Lookup(p.Username); err != nil {
		return comm.JobResult{Success: true, Output: "User does not exist"}
	}

	args := []string{p.Username}
	if p.DeleteFiles {
		args = append([]string{"-r"}, args...)
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "userdel", args...)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// SSH Key handlers

func (e *Executor) handleSSHKeyAdd(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
		Username  string `json:"username"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	u, err := user.Lookup(p.Username)
	if err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("user not found: %v", err)}
	}

	sshDir := filepath.Join(u.HomeDir, ".ssh")
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	os.MkdirAll(sshDir, 0700)

	// Read existing keys
	existing, _ := os.ReadFile(authKeysPath)
	keyLine := strings.TrimSpace(p.PublicKey)

	// Check if key exists
	if strings.Contains(string(existing), keyLine) {
		return comm.JobResult{Success: true, Output: "Key already exists"}
	}

	// Append key
	f, err := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}
	defer f.Close()

	keyWithComment := fmt.Sprintf("# hostman-key-id:%s\n%s\n", p.KeyID, keyLine)
	if _, err := f.WriteString(keyWithComment); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	e.RunCommand(ctx, "chown", "-R", p.Username+":"+p.Username, sshDir)

	return comm.JobResult{Success: true, Output: "Key added successfully"}
}

func (e *Executor) handleSSHKeyRemove(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		KeyID    string `json:"key_id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	u, err := user.Lookup(p.Username)
	if err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("user not found: %v", err)}
	}

	authKeysPath := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")

	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return comm.JobResult{Success: true, Output: "No authorized_keys file"}
		}
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Filter out the key
	lines := strings.Split(string(content), "\n")
	var newLines []string
	skipNext := false

	for _, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.Contains(line, fmt.Sprintf("hostman-key-id:%s", p.KeyID)) {
			skipNext = true
			continue
		}
		newLines = append(newLines, line)
	}

	if err := os.WriteFile(authKeysPath, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	return comm.JobResult{Success: true, Output: "Key removed successfully"}
}

func (e *Executor) handleSSHKeySync(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Username string `json:"username"`
		Keys     []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	u, err := user.Lookup(p.Username)
	if err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("user not found: %v", err)}
	}

	sshDir := filepath.Join(u.HomeDir, ".ssh")
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	os.MkdirAll(sshDir, 0700)

	var lines []string
	lines = append(lines, "# Managed by Hostman - Manual changes may be overwritten")

	for _, key := range p.Keys {
		lines = append(lines, fmt.Sprintf("# hostman-key-id:%s", key.KeyID))
		lines = append(lines, strings.TrimSpace(key.PublicKey))
	}

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	e.RunCommand(ctx, "chown", "-R", p.Username+":"+p.Username, sshDir)

	return comm.JobResult{Success: true, Output: fmt.Sprintf("Synced %d keys", len(p.Keys))}
}

// Firewall handlers

func (e *Executor) handleFirewallApply(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		RuleID    string `json:"rule_id"`
		Command   string `json:"command"` // e.g., "ufw allow in proto tcp to any port 22"
		IsRollback bool  `json:"is_rollback"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Parse and execute the UFW command safely
	parts := strings.Fields(p.Command)
	if len(parts) < 2 || parts[0] != "ufw" {
		return comm.JobResult{Success: false, Error: "invalid ufw command"}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, parts[0], parts[1:]...)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleFirewallRevert(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		RuleID  string `json:"rule_id"`
		Command string `json:"command"` // The delete command
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	parts := strings.Fields(p.Command)
	if len(parts) < 2 || parts[0] != "ufw" {
		return comm.JobResult{Success: false, Error: "invalid ufw command"}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, parts[0], parts[1:]...)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Deployment handler

func (e *Executor) handleDeploy(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID        string `json:"app_id"`
		Repository   string `json:"repository"`
		Branch       string `json:"branch"`
		CommitHash   string `json:"commit_hash"`
		DeployScript string `json:"deploy_script"`
		RootPath     string `json:"root_path"`
		Username     string `json:"username"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("app_id", p.AppID).
		Str("branch", p.Branch).
		Str("commit", p.CommitHash).
		Msg("Starting deployment")

	var output strings.Builder

	// Create releases directory
	releasesDir := filepath.Join(p.RootPath, "releases")
	releaseDir := filepath.Join(releasesDir, p.CommitHash)
	os.MkdirAll(releaseDir, 0755)

	// Clone repository
	out, _, err := e.RunCommandWithExitCode(ctx, "git", "clone", "--depth=1", "--branch="+p.Branch, p.Repository, releaseDir)
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
	}

	// Run deploy script if provided
	if p.DeployScript != "" {
		scriptPath := filepath.Join(releaseDir, ".hostman-deploy.sh")
		if err := os.WriteFile(scriptPath, []byte(p.DeployScript), 0755); err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
		}

		out, _, err = e.RunCommandWithExitCode(ctx, "bash", scriptPath)
		output.WriteString(out + "\n")
		if err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
		}
	}

	// Update symlink
	currentLink := filepath.Join(p.RootPath, "current")
	os.Remove(currentLink)
	if err := os.Symlink(releaseDir, currentLink); err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
	}

	// Set ownership
	e.RunCommand(ctx, "chown", "-R", p.Username+":"+p.Username, p.RootPath)

	output.WriteString("Deployment successful\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// Script handler

func (e *Executor) handleRunScript(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Script   string `json:"script"`
		Username string `json:"username"`
		WorkDir  string `json:"work_dir"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Write script to temp file
	tmpFile, err := os.CreateTemp("", "hostman-script-*.sh")
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(p.Script); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}
	tmpFile.Close()
	os.Chmod(tmpFile.Name(), 0755)

	// Run as specified user if provided
	var output string
	var exitCode int
	if p.Username != "" && p.Username != "root" {
		output, exitCode, err = e.RunCommandWithExitCode(ctx, "sudo", "-u", p.Username, "bash", tmpFile.Name())
	} else {
		output, exitCode, err = e.RunCommandWithExitCode(ctx, "bash", tmpFile.Name())
	}

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Helper functions

func getSystemdServiceName(serviceType, version string) string {
	switch serviceType {
	case "php":
		return fmt.Sprintf("php%s-fpm", version)
	case "nodejs":
		return "node"
	case "mysql":
		return "mysql"
	case "mariadb":
		return "mariadb"
	case "postgresql":
		return "postgresql"
	case "redis":
		return "redis-server"
	case "memcached":
		return "memcached"
	case "nginx":
		return "nginx"
	case "supervisor":
		return "supervisor"
	default:
		return serviceType
	}
}

func getInstallCommands(serviceType, version string, extensions []string) [][]string {
	switch serviceType {
	case "php":
		exts := extensions
		if len(exts) == 0 {
			exts = []string{"cli", "fpm", "mysql", "pgsql", "sqlite3", "gd", "curl", "mbstring", "xml", "zip", "bcmath", "intl", "readline", "opcache", "redis"}
		}
		var packages []string
		for _, ext := range exts {
			packages = append(packages, fmt.Sprintf("php%s-%s", version, ext))
		}
		return [][]string{
			{"add-apt-repository", "-y", "ppa:ondrej/php"},
			{"apt-get", "update"},
			append([]string{"apt-get", "install", "-y"}, packages...),
			{"systemctl", "enable", fmt.Sprintf("php%s-fpm", version)},
			{"systemctl", "start", fmt.Sprintf("php%s-fpm", version)},
		}
	case "nodejs":
		return [][]string{
			{"bash", "-c", fmt.Sprintf("curl -fsSL https://deb.nodesource.com/setup_%s.x | bash -", version)},
			{"apt-get", "install", "-y", "nodejs"},
			{"npm", "install", "-g", "npm@latest"},
			{"npm", "install", "-g", "pm2"},
		}
	case "mysql":
		return [][]string{
			{"apt-get", "install", "-y", "mysql-server"},
			{"systemctl", "enable", "mysql"},
			{"systemctl", "start", "mysql"},
		}
	case "mariadb":
		return [][]string{
			{"apt-get", "install", "-y", "mariadb-server"},
			{"systemctl", "enable", "mariadb"},
			{"systemctl", "start", "mariadb"},
		}
	case "postgresql":
		return [][]string{
			{"apt-get", "install", "-y", fmt.Sprintf("postgresql-%s", version)},
			{"systemctl", "enable", "postgresql"},
			{"systemctl", "start", "postgresql"},
		}
	case "redis":
		return [][]string{
			{"apt-get", "install", "-y", "redis-server"},
			{"systemctl", "enable", "redis-server"},
			{"systemctl", "start", "redis-server"},
		}
	case "nginx":
		return [][]string{
			{"apt-get", "install", "-y", "nginx"},
			{"systemctl", "enable", "nginx"},
			{"systemctl", "start", "nginx"},
		}
	case "supervisor":
		return [][]string{
			{"apt-get", "install", "-y", "supervisor"},
			{"systemctl", "enable", "supervisor"},
			{"systemctl", "start", "supervisor"},
		}
	case "composer":
		return [][]string{
			{"bash", "-c", "curl -sS https://getcomposer.org/installer | php"},
			{"mv", "composer.phar", "/usr/local/bin/composer"},
		}
	default:
		return [][]string{}
	}
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
