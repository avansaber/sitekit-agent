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

	"github.com/sitekit/sitekit-agent/internal/comm"
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

// PHP Extension handlers

func (e *Executor) handlePhpInstallExtension(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceID string `json:"service_id"`
		Version   string `json:"version"`
		Extension string `json:"extension"`
		Package   string `json:"package"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Install the PHP extension package
	output, exitCode, err := e.RunCommandWithExitCode(ctx,
		"apt-get", "install", "-y", p.Package)
	if err != nil {
		return comm.JobResult{Success: false, Output: output, Error: err.Error(), ExitCode: exitCode}
	}

	// Restart PHP-FPM to load the extension
	fpmService := fmt.Sprintf("php%s-fpm", p.Version)
	restartOutput, _, _ := e.RunCommandWithExitCode(ctx, "systemctl", "restart", fpmService)

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Installed %s\n%s\nRestarted %s:\n%s", p.Package, output, fpmService, restartOutput),
	}
}

func (e *Executor) handlePhpUninstallExtension(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ServiceID string `json:"service_id"`
		Version   string `json:"version"`
		Extension string `json:"extension"`
		Package   string `json:"package"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Prevent removing core extensions
	coreExtensions := []string{"cli", "fpm", "common"}
	for _, core := range coreExtensions {
		if p.Extension == core {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("Cannot uninstall core extension: %s", core)}
		}
	}

	// Remove the PHP extension package
	output, exitCode, err := e.RunCommandWithExitCode(ctx,
		"apt-get", "remove", "-y", p.Package)
	if err != nil {
		return comm.JobResult{Success: false, Output: output, Error: err.Error(), ExitCode: exitCode}
	}

	// Restart PHP-FPM to unload the extension
	fpmService := fmt.Sprintf("php%s-fpm", p.Version)
	restartOutput, _, _ := e.RunCommandWithExitCode(ctx, "systemctl", "restart", fpmService)

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Removed %s\n%s\nRestarted %s:\n%s", p.Package, output, fpmService, restartOutput),
	}
}

// Config validation handlers

func (e *Executor) handleValidateNginxConfig(ctx context.Context, payload json.RawMessage) comm.JobResult {
	// nginx -t tests the configuration syntax
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "nginx", "-t")

	return comm.JobResult{
		Success:  err == nil && exitCode == 0,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleValidatePhpConfig(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	version := p.Version
	if version == "" {
		version = "8.3" // Default to 8.3
	}

	// php-fpmX.Y -t tests the PHP-FPM configuration
	fpmBin := fmt.Sprintf("php-fpm%s", version)
	output, exitCode, err := e.RunCommandWithExitCode(ctx, fpmBin, "-t")

	return comm.JobResult{
		Success:  err == nil && exitCode == 0,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
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

	keyWithComment := fmt.Sprintf("# sitekit-key-id:%s\n%s\n", p.KeyID, keyLine)
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
		if strings.Contains(line, fmt.Sprintf("sitekit-key-id:%s", p.KeyID)) {
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
	lines = append(lines, "# Managed by SiteKit - Manual changes may be overwritten")

	for _, key := range p.Keys {
		lines = append(lines, fmt.Sprintf("# sitekit-key-id:%s", key.KeyID))
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

// Web Application handlers

func (e *Executor) handleCreateWebApp(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID       string `json:"app_id"`
		Domain      string `json:"domain"`
		Username    string `json:"username"`
		RootPath    string `json:"root_path"`
		PublicPath  string `json:"public_path"`
		PhpVersion  string `json:"php_version"`
		AppType     string `json:"app_type"` // php, static, nodejs
		NginxConfig string `json:"nginx_config"`
		FpmConfig   string `json:"fpm_config"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("app_id", p.AppID).
		Str("domain", p.Domain).
		Msg("Creating web application")

	var output strings.Builder

	// Create home directory first (useradd needs it to exist or be creatable)
	if err := os.MkdirAll(p.RootPath, 0755); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to create home directory %s: %v", p.RootPath, err)}
	}

	// Create system user if it doesn't exist
	if _, _, err := e.RunCommandWithExitCode(ctx, "id", p.Username); err != nil {
		// User doesn't exist, create it (don't use -m since we already created the directory)
		out, _, err := e.RunCommandWithExitCode(ctx, "useradd", "-r", "-d", p.RootPath, "-s", "/bin/bash", p.Username)
		if err != nil {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to create user %s: %v - %s", p.Username, err, out)}
		}
		output.WriteString(fmt.Sprintf("Created system user: %s\n", p.Username))
	} else {
		output.WriteString(fmt.Sprintf("User %s already exists\n", p.Username))
	}

	// Create directory structure
	dirs := []string{
		p.RootPath,
		filepath.Join(p.RootPath, "releases"),
		filepath.Join(p.RootPath, "shared"),
		filepath.Join(p.RootPath, "logs"),
		filepath.Join(p.RootPath, "current", p.PublicPath),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to create %s: %v", dir, err)}
		}
	}
	output.WriteString("Created directory structure\n")

	// Write Nginx config
	nginxPath := fmt.Sprintf("/etc/nginx/sites-available/%s.conf", p.Domain)
	if err := os.WriteFile(nginxPath, []byte(p.NginxConfig), 0644); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write nginx config: %v", err)}
	}

	// Enable site
	enabledPath := fmt.Sprintf("/etc/nginx/sites-enabled/%s.conf", p.Domain)
	os.Remove(enabledPath)
	if err := os.Symlink(nginxPath, enabledPath); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to enable site: %v", err)}
	}
	output.WriteString("Nginx config installed\n")

	// Write PHP-FPM pool config if PHP app
	if p.AppType == "php" && p.FpmConfig != "" {
		// Create FPM log directory
		fpmLogDir := fmt.Sprintf("/var/log/php%s-fpm", p.PhpVersion)
		if err := os.MkdirAll(fpmLogDir, 0755); err != nil {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to create fpm log dir: %v", err)}
		}

		fpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.PhpVersion, p.AppID)
		if err := os.WriteFile(fpmPath, []byte(p.FpmConfig), 0644); err != nil {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write fpm config: %v", err)}
		}
		output.WriteString("PHP-FPM pool config installed\n")

		// Create default index.php if no files exist
		indexPath := filepath.Join(p.RootPath, "current", p.PublicPath, "index.php")
		if _, err := os.Stat(indexPath); os.IsNotExist(err) {
			defaultIndex := fmt.Sprintf("<?php\necho '<h1>Welcome to %s</h1>';\necho '<p>PHP Version: ' . phpversion() . '</p>';\necho '<p>Server Time: ' . date('Y-m-d H:i:s') . '</p>';\n", p.Domain)
			if err := os.WriteFile(indexPath, []byte(defaultIndex), 0644); err != nil {
				output.WriteString(fmt.Sprintf("Warning: failed to create default index.php: %v\n", err))
			} else {
				output.WriteString("Created default index.php\n")
			}
		}

		// Reload PHP-FPM
		e.RunCommand(ctx, "systemctl", "reload", fmt.Sprintf("php%s-fpm", p.PhpVersion))
	}

	// Test and reload Nginx
	out, _, err := e.RunCommandWithExitCode(ctx, "nginx", "-t")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "nginx config test failed"}
	}

	e.RunCommand(ctx, "systemctl", "reload", "nginx")
	output.WriteString("Nginx reloaded successfully\n")

	// Set ownership
	e.RunCommand(ctx, "chown", "-R", p.Username+":"+p.Username, p.RootPath)

	return comm.JobResult{Success: true, Output: output.String()}
}

func (e *Executor) handleUpdateWebAppConfig(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID         string `json:"app_id"`
		Domain        string `json:"domain"`
		PhpVersion    string `json:"php_version"`
		OldPhpVersion string `json:"old_php_version"`
		NginxConfig   string `json:"nginx_config"`
		FpmConfig     string `json:"fpm_config"`
		Username      string `json:"username"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Update Nginx config
	nginxPath := fmt.Sprintf("/etc/nginx/sites-available/%s.conf", p.Domain)
	if err := os.WriteFile(nginxPath, []byte(p.NginxConfig), 0644); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write nginx config: %v", err)}
	}
	output.WriteString("Nginx config updated\n")

	// If PHP version changed, remove old FPM pool config
	if p.OldPhpVersion != "" && p.OldPhpVersion != p.PhpVersion {
		oldFpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.OldPhpVersion, p.AppID)
		if err := os.Remove(oldFpmPath); err != nil && !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", oldFpmPath).Msg("Failed to remove old FPM pool config")
		} else {
			output.WriteString(fmt.Sprintf("Removed old PHP %s FPM pool config\n", p.OldPhpVersion))
		}
		// Reload old PHP-FPM to release resources
		e.RunCommand(ctx, "systemctl", "reload", fmt.Sprintf("php%s-fpm", p.OldPhpVersion))
	}

	// Update PHP-FPM config if provided
	if p.FpmConfig != "" {
		fpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.PhpVersion, p.AppID)
		if err := os.WriteFile(fpmPath, []byte(p.FpmConfig), 0644); err != nil {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write fpm config: %v", err)}
		}
		e.RunCommand(ctx, "systemctl", "reload", fmt.Sprintf("php%s-fpm", p.PhpVersion))
		output.WriteString("PHP-FPM config updated and reloaded\n")
	}

	// Test and reload Nginx
	out, _, err := e.RunCommandWithExitCode(ctx, "nginx", "-t")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "nginx config test failed"}
	}

	e.RunCommand(ctx, "systemctl", "reload", "nginx")
	output.WriteString("Nginx reloaded successfully\n")

	return comm.JobResult{Success: true, Output: output.String()}
}

func (e *Executor) handleDeleteWebApp(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID       string `json:"app_id"`
		Domain      string `json:"domain"`
		Username    string `json:"username"`
		PhpVersion  string `json:"php_version"`
		DeleteFiles bool   `json:"delete_files"`
		RootPath    string `json:"root_path"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Remove Nginx config
	nginxPath := fmt.Sprintf("/etc/nginx/sites-available/%s.conf", p.Domain)
	enabledPath := fmt.Sprintf("/etc/nginx/sites-enabled/%s.conf", p.Domain)
	os.Remove(enabledPath)
	os.Remove(nginxPath)
	output.WriteString("Nginx config removed\n")

	// Remove PHP-FPM pool config
	if p.PhpVersion != "" {
		fpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.PhpVersion, p.AppID)
		os.Remove(fpmPath)
		e.RunCommand(ctx, "systemctl", "reload", fmt.Sprintf("php%s-fpm", p.PhpVersion))
		output.WriteString("PHP-FPM pool config removed\n")
	}

	// Reload Nginx
	e.RunCommand(ctx, "systemctl", "reload", "nginx")
	output.WriteString("Nginx reloaded\n")

	// Delete files if requested
	if p.DeleteFiles && p.RootPath != "" {
		if err := os.RemoveAll(p.RootPath); err != nil {
			output.WriteString(fmt.Sprintf("Warning: failed to delete files: %v\n", err))
		} else {
			output.WriteString("Application files deleted\n")
		}
	}

	return comm.JobResult{Success: true, Output: output.String()}
}

// SSL Certificate handler

func (e *Executor) handleIssueSSL(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		CertID    string   `json:"certificate_id"` // Match SaaS payload
		Domains   []string `json:"domains"`
		Email     string   `json:"email"`
		Webroot   string   `json:"webroot"`
		Staging   bool     `json:"staging"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	if len(p.Domains) == 0 {
		return comm.JobResult{Success: false, Error: "at least one domain is required"}
	}

	log.Info().
		Strs("domains", p.Domains).
		Msg("Issuing SSL certificate")

	// Fix permissions on webroot path to ensure nginx can serve ACME challenge
	// This fixes the common issue where /home/sitekit has 750 permissions
	if err := e.fixWebrootPermissions(p.Webroot); err != nil {
		log.Warn().Err(err).Msg("Failed to fix webroot permissions, continuing anyway")
	}

	args := []string{
		"certonly",
		"--webroot",
		"--webroot-path", p.Webroot,
		"--email", p.Email,
		"--agree-tos",
		"--non-interactive",
	}

	if p.Staging {
		args = append(args, "--staging")
	}

	for _, domain := range p.Domains {
		args = append(args, "-d", domain)
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "certbot", args...)

	if err != nil {
		// Try to get more detailed error from certbot log
		detailedError := e.getCertbotError(output)
		if detailedError == "" {
			detailedError = err.Error()
		}
		return comm.JobResult{
			Success:  false,
			Output:   output,
			Error:    detailedError,
			ExitCode: exitCode,
		}
	}

	// Return certificate paths
	primaryDomain := p.Domains[0]
	certPath := fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", primaryDomain)
	keyPath := fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", primaryDomain)

	return comm.JobResult{
		Success: true,
		Output:  output,
		Data: map[string]interface{}{
			"certificate_path": certPath,
			"private_key_path": keyPath,
		},
	}
}

func (e *Executor) handleRenewSSL(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		CertID  string `json:"cert_id"`
		Domain  string `json:"domain"`
		Force   bool   `json:"force"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	args := []string{"renew", "--cert-name", p.Domain, "--non-interactive"}
	if p.Force {
		args = append(args, "--force-renewal")
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "certbot", args...)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Install custom SSL certificate (not Let's Encrypt)
func (e *Executor) handleInstallSSL(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		CertificateID string `json:"certificate_id"`
		Domain        string `json:"domain"`
		Certificate   string `json:"certificate"`
		PrivateKey    string `json:"private_key"`
		Chain         string `json:"chain"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Create SSL directory
	sslDir := fmt.Sprintf("/etc/ssl/sitekit/%s", p.Domain)
	if err := os.MkdirAll(sslDir, 0700); err != nil {
		return comm.JobResult{Success: false, Error: "Failed to create SSL directory: " + err.Error()}
	}

	var output strings.Builder

	// Write certificate
	certPath := filepath.Join(sslDir, "fullchain.pem")
	certContent := p.Certificate
	if p.Chain != "" {
		certContent = p.Certificate + "\n" + p.Chain
	}
	if err := os.WriteFile(certPath, []byte(certContent), 0644); err != nil {
		return comm.JobResult{Success: false, Error: "Failed to write certificate: " + err.Error()}
	}
	output.WriteString(fmt.Sprintf("Certificate written to %s\n", certPath))

	// Write private key
	keyPath := filepath.Join(sslDir, "privkey.pem")
	if err := os.WriteFile(keyPath, []byte(p.PrivateKey), 0600); err != nil {
		return comm.JobResult{Success: false, Error: "Failed to write private key: " + err.Error()}
	}
	output.WriteString(fmt.Sprintf("Private key written to %s\n", keyPath))

	// Reload nginx to pick up new certificate
	reloadOut, _, _ := e.RunCommandWithExitCode(ctx, "systemctl", "reload", "nginx")
	output.WriteString(reloadOut)
	output.WriteString("Nginx reloaded\n")

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
		Data: map[string]interface{}{
			"cert_path": certPath,
			"key_path":  keyPath,
		},
	}
}

// Database handlers

// getMySQLArgs returns the common args for MySQL commands with authentication using sitekit user
func (e *Executor) getMySQLArgs(query string) []string {
	if e.mysqlConfig.User != "" && e.mysqlConfig.Password != "" {
		return []string{"-u", e.mysqlConfig.User, "-p" + e.mysqlConfig.Password, "-e", query}
	}
	// Fallback to reading root password from file (for backwards compatibility)
	data, err := os.ReadFile("/opt/sitekit/config/.mysql_root")
	if err == nil {
		password := strings.TrimSpace(string(data))
		if password != "" {
			return []string{"-u", "root", "-p" + password, "-e", query}
		}
	}
	log.Warn().Msg("No MySQL credentials available")
	return []string{"-e", query}
}

func (e *Executor) handleCreateDatabase(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DatabaseID   string `json:"database_id"`
		DatabaseName string `json:"database_name"`
		DatabaseType string `json:"database_type"` // mysql, mariadb, postgresql
		Username     string `json:"username"`
		Password     string `json:"password"`
		Host         string `json:"host"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("database", p.DatabaseName).
		Str("type", p.DatabaseType).
		Msg("Creating database")

	var output strings.Builder

	switch p.DatabaseType {
	case "mysql", "mariadb":
		// Create database
		createDB := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", p.DatabaseName)
		out, _, err := e.RunCommandWithExitCode(ctx, "mysql", e.getMySQLArgs(createDB)...)
		output.WriteString(out + "\n")
		if err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
		}

		// Create user and grant privileges
		if p.Username != "" && p.Password != "" {
			host := p.Host
			if host == "" {
				host = "localhost"
			}
			createUser := fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s';", p.Username, host, p.Password)
			out, _, err = e.RunCommandWithExitCode(ctx, "mysql", e.getMySQLArgs(createUser)...)
			output.WriteString(out + "\n")
			if err != nil {
				return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
			}

			grant := fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s'; FLUSH PRIVILEGES;", p.DatabaseName, p.Username, host)
			out, _, err = e.RunCommandWithExitCode(ctx, "mysql", e.getMySQLArgs(grant)...)
			output.WriteString(out + "\n")
			if err != nil {
				return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
			}
		}

	case "postgresql":
		// Create database
		out, _, _ := e.RunCommandWithExitCode(ctx, "sudo", "-u", "postgres", "psql", "-c",
			fmt.Sprintf("CREATE DATABASE \"%s\";", p.DatabaseName))
		output.WriteString(out + "\n")

		// Create user and grant privileges
		if p.Username != "" && p.Password != "" {
			out, _, _ = e.RunCommandWithExitCode(ctx, "sudo", "-u", "postgres", "psql", "-c",
				fmt.Sprintf("CREATE USER \"%s\" WITH PASSWORD '%s';", p.Username, p.Password))
			output.WriteString(out + "\n")

			out, _, _ = e.RunCommandWithExitCode(ctx, "sudo", "-u", "postgres", "psql", "-c",
				fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE \"%s\" TO \"%s\";", p.DatabaseName, p.Username))
			output.WriteString(out + "\n")
		}

	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.DatabaseType)}
	}

	output.WriteString("Database created successfully\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

func (e *Executor) handleDeleteDatabase(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DatabaseID   string `json:"database_id"`
		DatabaseName string `json:"database_name"`
		DatabaseType string `json:"database_type"`
		Username     string `json:"username"`
		Host         string `json:"host"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	switch p.DatabaseType {
	case "mysql", "mariadb":
		// Drop user if exists
		if p.Username != "" {
			host := p.Host
			if host == "" {
				host = "localhost"
			}
			dropUser := fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s';", p.Username, host)
			out, _, _ := e.RunCommandWithExitCode(ctx, "mysql", e.getMySQLArgs(dropUser)...)
			output.WriteString(out + "\n")
		}

		// Drop database
		dropDB := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", p.DatabaseName)
		out, _, err := e.RunCommandWithExitCode(ctx, "mysql", e.getMySQLArgs(dropDB)...)
		output.WriteString(out + "\n")
		if err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
		}

	case "postgresql":
		// Drop user if exists
		if p.Username != "" {
			out, _, _ := e.RunCommandWithExitCode(ctx, "sudo", "-u", "postgres", "psql", "-c",
				fmt.Sprintf("DROP USER IF EXISTS \"%s\";", p.Username))
			output.WriteString(out + "\n")
		}

		// Drop database
		out, _, _ := e.RunCommandWithExitCode(ctx, "sudo", "-u", "postgres", "psql", "-c",
			fmt.Sprintf("DROP DATABASE IF EXISTS \"%s\";", p.DatabaseName))
		output.WriteString(out + "\n")

	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.DatabaseType)}
	}

	output.WriteString("Database deleted successfully\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// Crontab handler

func (e *Executor) handleSyncCrontab(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Username string `json:"username"`
		Entries  []struct {
			Schedule string `json:"schedule"`
			Command  string `json:"command"`
			Enabled  bool   `json:"enabled"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var crontab strings.Builder
	crontab.WriteString("# Managed by SiteKit - Do not edit directly\n")
	crontab.WriteString("SHELL=/bin/bash\n")
	crontab.WriteString("PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n")

	for _, entry := range p.Entries {
		if !entry.Enabled {
			crontab.WriteString("# ")
		}
		crontab.WriteString(fmt.Sprintf("%s %s\n", entry.Schedule, entry.Command))
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "crontab-*")
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(crontab.String()); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}
	tmpFile.Close()

	// Install crontab for user
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "crontab", "-u", p.Username, tmpFile.Name())

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Rollback handler

func (e *Executor) handleRollbackDeployment(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		WebAppID   string `json:"web_app_id"`
		AppPath    string `json:"app_path"`
		CommitHash string `json:"commit_hash"` // Release to rollback to
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Handle short commit hash (12 chars)
	releaseHash := p.CommitHash
	if len(releaseHash) > 12 {
		releaseHash = releaseHash[:12]
	}
	releaseDir := filepath.Join(p.AppPath, "releases", releaseHash)

	// Check if release exists
	if _, err := os.Stat(releaseDir); os.IsNotExist(err) {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("release %s not found", releaseHash)}
	}

	// Atomic symlink swap
	currentLink := filepath.Join(p.AppPath, "current")
	tempLink := filepath.Join(p.AppPath, ".current.tmp")

	os.Remove(tempLink)
	if err := os.Symlink(releaseDir, tempLink); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	if err := os.Rename(tempLink, currentLink); err != nil {
		os.Remove(tempLink)
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Rolled back to release %s", releaseHash),
	}
}

// Cleanup old releases
func (e *Executor) handleCleanupReleases(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		WebAppID string `json:"web_app_id"`
		AppPath  string `json:"app_path"`
		Keep     int    `json:"keep"` // Number of releases to keep
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	if p.Keep < 1 {
		p.Keep = 5
	}

	releasesDir := filepath.Join(p.AppPath, "releases")
	entries, err := os.ReadDir(releasesDir)
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Get current release (symlink target)
	currentLink := filepath.Join(p.AppPath, "current")
	currentTarget, _ := os.Readlink(currentLink)
	currentRelease := filepath.Base(currentTarget)

	// Sort by modification time (oldest first)
	type releaseInfo struct {
		name    string
		modTime int64
	}
	var releases []releaseInfo
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != currentRelease {
			info, _ := entry.Info()
			releases = append(releases, releaseInfo{entry.Name(), info.ModTime().Unix()})
		}
	}

	// Remove oldest releases beyond keep limit
	if len(releases) > p.Keep-1 {
		// Sort by modTime ascending
		for i := 0; i < len(releases)-1; i++ {
			for j := i + 1; j < len(releases); j++ {
				if releases[i].modTime > releases[j].modTime {
					releases[i], releases[j] = releases[j], releases[i]
				}
			}
		}

		toRemove := len(releases) - (p.Keep - 1)
		var removed []string
		for i := 0; i < toRemove; i++ {
			path := filepath.Join(releasesDir, releases[i].name)
			if err := os.RemoveAll(path); err == nil {
				removed = append(removed, releases[i].name)
			}
		}

		return comm.JobResult{
			Success: true,
			Output:  fmt.Sprintf("Removed %d old releases: %v", len(removed), removed),
		}
	}

	return comm.JobResult{Success: true, Output: "No releases to clean up"}
}

// Deployment handler

func (e *Executor) handleDeploy(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DeploymentID      string   `json:"deployment_id"`
		AppPath           string   `json:"app_path"`
		Username          string   `json:"username"`
		Repository        string   `json:"repository"`
		Branch            string   `json:"branch"`
		CommitHash        string   `json:"commit_hash"`
		SSHUrl            string   `json:"ssh_url"`
		DeployKey         string   `json:"deploy_key"`
		SharedFiles       []string `json:"shared_files"`
		SharedDirectories []string `json:"shared_directories"`
		BuildScript       string   `json:"build_script"`
		PHPVersion        string   `json:"php_version"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("deployment_id", p.DeploymentID).
		Str("branch", p.Branch).
		Str("commit", p.CommitHash).
		Msg("Starting deployment")

	var output strings.Builder

	// Setup directories
	releasesDir := filepath.Join(p.AppPath, "releases")
	sharedDir := filepath.Join(p.AppPath, "shared")
	releaseDir := filepath.Join(releasesDir, p.CommitHash[:12])
	os.MkdirAll(releaseDir, 0755)
	os.MkdirAll(sharedDir, 0755)

	// Setup deploy key for SSH authentication
	if p.DeployKey != "" {
		keyPath := filepath.Join(os.TempDir(), fmt.Sprintf("sitekit-deploy-%s", p.DeploymentID))
		if err := os.WriteFile(keyPath, []byte(p.DeployKey), 0600); err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to write deploy key: " + err.Error()}
		}
		defer os.Remove(keyPath)

		// Set GIT_SSH_COMMAND for this deployment
		os.Setenv("GIT_SSH_COMMAND", fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", keyPath))
		defer os.Unsetenv("GIT_SSH_COMMAND")
	}

	// Clone repository using SSH URL
	cloneUrl := p.SSHUrl
	if cloneUrl == "" {
		cloneUrl = p.Repository
	}
	output.WriteString(fmt.Sprintf("Cloning %s (branch: %s)...\n", p.Repository, p.Branch))
	out, _, err := e.RunCommandWithExitCode(ctx, "git", "clone", "--depth=1", "--branch="+p.Branch, cloneUrl, releaseDir)
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Clone failed: " + err.Error()}
	}

	// Set ownership for the app directory
	if p.Username != "" {
		output.WriteString(fmt.Sprintf("Setting ownership to %s...\n", p.Username))
		if out, err := e.RunCommand(ctx, "chown", "-R", p.Username+":"+p.Username, p.AppPath); err != nil {
			log.Warn().Err(err).Str("output", out).Msg("Failed to set ownership")
		}
	}

	// Setup shared directories (create in shared and symlink to release)
	for _, dir := range p.SharedDirectories {
		sharedPath := filepath.Join(sharedDir, dir)
		releasePath := filepath.Join(releaseDir, dir)

		// Create shared directory if it doesn't exist
		os.MkdirAll(sharedPath, 0755)

		// Remove release path if exists (could be from clone)
		os.RemoveAll(releasePath)

		// Create parent directory for symlink
		os.MkdirAll(filepath.Dir(releasePath), 0755)

		// Create symlink
		if err := os.Symlink(sharedPath, releasePath); err != nil {
			log.Warn().Err(err).Str("dir", dir).Msg("Failed to symlink shared directory")
		} else {
			output.WriteString(fmt.Sprintf("Linked shared directory: %s\n", dir))
		}
	}

	// Setup shared files (copy from release to shared on first deploy, then symlink)
	for _, file := range p.SharedFiles {
		sharedPath := filepath.Join(sharedDir, file)
		releasePath := filepath.Join(releaseDir, file)

		// If shared file doesn't exist but release has it, copy it
		if _, err := os.Stat(sharedPath); os.IsNotExist(err) {
			if _, err := os.Stat(releasePath); err == nil {
				os.MkdirAll(filepath.Dir(sharedPath), 0755)
				e.RunCommand(ctx, "cp", releasePath, sharedPath)
			}
		}

		// Remove release file and create symlink
		os.Remove(releasePath)
		os.MkdirAll(filepath.Dir(releasePath), 0755)
		if err := os.Symlink(sharedPath, releasePath); err != nil {
			log.Warn().Err(err).Str("file", file).Msg("Failed to symlink shared file")
		} else {
			output.WriteString(fmt.Sprintf("Linked shared file: %s\n", file))
		}
	}

	// Run build script if provided
	if p.BuildScript != "" {
		output.WriteString("Running build script...\n")
		scriptPath := filepath.Join(releaseDir, ".sitekit-deploy.sh")
		scriptContent := "#!/bin/bash\nset -e\ncd " + releaseDir + "\n"
		if p.PHPVersion != "" {
			scriptContent += fmt.Sprintf("export PATH=/usr/bin/php%s:$PATH\n", p.PHPVersion)
		}
		scriptContent += p.BuildScript

		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to write build script: " + err.Error()}
		}

		out, _, err = e.RunCommandWithExitCode(ctx, "bash", scriptPath)
		output.WriteString(out + "\n")
		os.Remove(scriptPath)
		if err != nil {
			return comm.JobResult{Success: false, Output: output.String(), Error: "Build script failed: " + err.Error()}
		}
	}

	// Atomic symlink swap
	currentLink := filepath.Join(p.AppPath, "current")
	tempLink := filepath.Join(p.AppPath, ".current.tmp")

	// Check if current is a directory (not a symlink) and remove it
	if info, err := os.Lstat(currentLink); err == nil {
		if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			// It's a real directory, not a symlink - move to releases as backup
			backupPath := filepath.Join(p.AppPath, "releases", "initial_backup")
			os.Rename(currentLink, backupPath)
			output.WriteString("Moved existing current directory to releases/initial_backup\n")
		}
	}

	// Create temp symlink
	os.Remove(tempLink)
	if err := os.Symlink(releaseDir, tempLink); err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to create symlink: " + err.Error()}
	}

	// Atomic rename (this works when replacing a symlink or when target doesn't exist)
	if err := os.Rename(tempLink, currentLink); err != nil {
		os.Remove(tempLink)
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to activate release: " + err.Error()}
	}

	output.WriteString(fmt.Sprintf("Deployment successful! Release: %s\n", p.CommitHash[:12]))
	return comm.JobResult{
		Success: true,
		Output:  output.String(),
		Data: map[string]interface{}{
			"release_path": releaseDir,
		},
	}
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
	tmpFile, err := os.CreateTemp("", "sitekit-script-*.sh")
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
	case "apache":
		return "apache2"
	case "supervisor":
		return "supervisor"
	case "beanstalkd":
		return "beanstalkd"
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

// Database user handlers

func (e *Executor) handleCreateDatabaseUser(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DBName    string `json:"db_name"`
		Type      string `json:"type"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		CanRemote bool   `json:"can_remote"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var cmd string
	host := "localhost"
	if p.CanRemote {
		host = "%"
	}

	switch p.Type {
	case "mysql", "mariadb":
		cmd = fmt.Sprintf(
			"mysql -e \"CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s'; GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%s'; FLUSH PRIVILEGES;\"",
			p.Username, host, p.Password, p.DBName, p.Username, host,
		)
	case "postgresql":
		cmd = fmt.Sprintf(
			"sudo -u postgres psql -c \"CREATE USER %s WITH PASSWORD '%s'; GRANT ALL PRIVILEGES ON DATABASE %s TO %s;\"",
			p.Username, p.Password, p.DBName, p.Username,
		)
	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.Type)}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", cmd)

	log.Info().Str("username", p.Username).Str("database", p.DBName).Msg("Created database user")

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleDeleteDatabaseUser(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Type     string `json:"type"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var cmd string
	switch p.Type {
	case "mysql", "mariadb":
		cmd = fmt.Sprintf("mysql -e \"DROP USER IF EXISTS '%s'@'localhost'; DROP USER IF EXISTS '%s'@'%%'; FLUSH PRIVILEGES;\"", p.Username, p.Username)
	case "postgresql":
		cmd = fmt.Sprintf("sudo -u postgres psql -c \"DROP USER IF EXISTS %s;\"", p.Username)
	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.Type)}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", cmd)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleExportDatabase(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DBName           string `json:"db_name"`
		Type             string `json:"type"`
		IncludeStructure bool   `json:"include_structure"`
		IncludeData      bool   `json:"include_data"`
		Compress         bool   `json:"compress"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	timestamp := strings.ReplaceAll(strings.ReplaceAll(strings.Split(fmt.Sprintf("%v", ctx.Value("timestamp")), ".")[0], "-", ""), " ", "_")
	if timestamp == "" {
		timestamp = "export"
	}
	outputFile := fmt.Sprintf("/tmp/%s_%s.sql", p.DBName, timestamp)

	var cmd string
	switch p.Type {
	case "mysql", "mariadb":
		args := []string{}
		if e.mysqlConfig.User != "" && e.mysqlConfig.Password != "" {
			args = append(args, "-u", e.mysqlConfig.User, "-p'"+e.mysqlConfig.Password+"'")
		}
		if !p.IncludeData {
			args = append(args, "--no-data")
		}
		if !p.IncludeStructure {
			args = append(args, "--no-create-info")
		}
		cmd = fmt.Sprintf("mysqldump %s %s > %s", strings.Join(args, " "), p.DBName, outputFile)
	case "postgresql":
		args := []string{}
		if !p.IncludeData {
			args = append(args, "--schema-only")
		}
		if !p.IncludeStructure {
			args = append(args, "--data-only")
		}
		cmd = fmt.Sprintf("sudo -u postgres pg_dump %s %s > %s", strings.Join(args, " "), p.DBName, outputFile)
	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.Type)}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", cmd)
	if err != nil {
		return comm.JobResult{Success: false, Output: output, Error: errToString(err), ExitCode: exitCode}
	}

	if p.Compress {
		_, _, gzErr := e.RunCommandWithExitCode(ctx, "gzip", "-f", outputFile)
		if gzErr == nil {
			outputFile = outputFile + ".gz"
		}
	}

	return comm.JobResult{
		Success:  true,
		Output:   output,
		ExitCode: exitCode,
		Data:     map[string]interface{}{"file": outputFile},
	}
}

func (e *Executor) handleImportDatabase(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DBName       string `json:"db_name"`
		Type         string `json:"type"`
		FilePath     string `json:"file_path"`
		DropExisting bool   `json:"drop_existing"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Check if file is gzipped
	importFile := p.FilePath
	if strings.HasSuffix(p.FilePath, ".gz") {
		unzippedFile := strings.TrimSuffix(p.FilePath, ".gz")
		_, _, err := e.RunCommandWithExitCode(ctx, "gunzip", "-k", "-f", p.FilePath)
		if err != nil {
			return comm.JobResult{Success: false, Error: "failed to decompress file"}
		}
		importFile = unzippedFile
	}

	var cmd string
	switch p.Type {
	case "mysql", "mariadb":
		if p.DropExisting {
			dropCmd := fmt.Sprintf("mysql -e \"DROP DATABASE IF EXISTS %s; CREATE DATABASE %s;\"", p.DBName, p.DBName)
			e.RunCommandWithExitCode(ctx, "bash", "-c", dropCmd)
		}
		cmd = fmt.Sprintf("mysql %s < %s", p.DBName, importFile)
	case "postgresql":
		if p.DropExisting {
			dropCmd := fmt.Sprintf("sudo -u postgres psql -c \"DROP DATABASE IF EXISTS %s; CREATE DATABASE %s;\"", p.DBName, p.DBName)
			e.RunCommandWithExitCode(ctx, "bash", "-c", dropCmd)
		}
		cmd = fmt.Sprintf("sudo -u postgres psql %s < %s", p.DBName, importFile)
	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.Type)}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", cmd)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleOptimizeDatabase(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DBName string `json:"db_name"`
		Type   string `json:"type"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var cmd string
	switch p.Type {
	case "mysql", "mariadb":
		if e.mysqlConfig.User != "" && e.mysqlConfig.Password != "" {
			cmd = fmt.Sprintf("mysqlcheck -u %s -p'%s' --optimize %s", e.mysqlConfig.User, e.mysqlConfig.Password, p.DBName)
		} else {
			cmd = fmt.Sprintf("mysqlcheck --optimize %s", p.DBName)
		}
	case "postgresql":
		cmd = fmt.Sprintf("sudo -u postgres psql -d %s -c \"VACUUM ANALYZE;\"", p.DBName)
	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.Type)}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", cmd)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Firewall handlers

func (e *Executor) handleEnableFirewall(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		DefaultIncoming string `json:"default_incoming"`
		DefaultOutgoing string `json:"default_outgoing"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Set defaults
	if p.DefaultIncoming != "" {
		e.RunCommandWithExitCode(ctx, "ufw", "default", p.DefaultIncoming, "incoming")
	}
	if p.DefaultOutgoing != "" {
		e.RunCommandWithExitCode(ctx, "ufw", "default", p.DefaultOutgoing, "outgoing")
	}

	// Enable UFW (non-interactive)
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", "echo 'y' | ufw enable")

	log.Info().Msg("Firewall enabled")

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleApplyFirewallRule(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		RuleID  string `json:"rule_id"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", p.Command)

	log.Info().Str("rule_id", p.RuleID).Str("command", p.Command).Msg("Applied firewall rule")

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleRevertFirewallRule(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		RuleID  string `json:"rule_id"`
		Command string `json:"command"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", p.Command)

	log.Info().Str("rule_id", p.RuleID).Str("reason", p.Reason).Msg("Reverted firewall rule")

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Database backup handler

func (e *Executor) handleDatabaseBackup(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		BackupID     string `json:"backup_id"`
		DatabaseID   string `json:"database_id"`
		DatabaseName string `json:"database_name"`
		DatabaseType string `json:"database_type"`
		Filename     string `json:"filename"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().
		Str("backup_id", p.BackupID).
		Str("database", p.DatabaseName).
		Str("type", p.DatabaseType).
		Msg("Creating database backup")

	// Create backup directory
	backupDir := "/opt/sitekit/backups/databases"
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return comm.JobResult{Success: false, Error: "Failed to create backup directory: " + err.Error()}
	}

	outputFile := filepath.Join(backupDir, p.Filename)
	uncompressedFile := strings.TrimSuffix(outputFile, ".gz")

	var cmd string
	switch p.DatabaseType {
	case "mysql", "mariadb":
		if e.mysqlConfig.User != "" && e.mysqlConfig.Password != "" {
			cmd = fmt.Sprintf("mysqldump -u %s -p'%s' --single-transaction --quick --lock-tables=false %s > %s", e.mysqlConfig.User, e.mysqlConfig.Password, p.DatabaseName, uncompressedFile)
		} else {
			cmd = fmt.Sprintf("mysqldump --single-transaction --quick --lock-tables=false %s > %s", p.DatabaseName, uncompressedFile)
		}
	case "postgresql":
		cmd = fmt.Sprintf("sudo -u postgres pg_dump --format=plain %s > %s", p.DatabaseName, uncompressedFile)
	default:
		return comm.JobResult{Success: false, Error: fmt.Sprintf("unsupported database type: %s", p.DatabaseType)}
	}

	output, exitCode, err := e.RunCommandWithExitCode(ctx, "bash", "-c", cmd)
	if err != nil {
		return comm.JobResult{
			Success:  false,
			Output:   output,
			Error:    "Backup failed: " + err.Error(),
			ExitCode: exitCode,
		}
	}

	// Compress the backup
	if strings.HasSuffix(p.Filename, ".gz") {
		_, _, gzErr := e.RunCommandWithExitCode(ctx, "gzip", "-f", uncompressedFile)
		if gzErr != nil {
			return comm.JobResult{
				Success: false,
				Output:  output,
				Error:   "Failed to compress backup: " + gzErr.Error(),
			}
		}
	}

	// Get file size
	fileInfo, err := os.Stat(outputFile)
	var sizeBytes int64
	if err == nil {
		sizeBytes = fileInfo.Size()
	}

	log.Info().
		Str("backup_id", p.BackupID).
		Str("path", outputFile).
		Int64("size_bytes", sizeBytes).
		Msg("Database backup completed")

	return comm.JobResult{
		Success: true,
		Output:  outputFile,
		Data: map[string]interface{}{
			"path":       outputFile,
			"size_bytes": sizeBytes,
		},
	}
}

// Environment file handler

func (e *Executor) handleUpdateEnvFile(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppPath string `json:"app_path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	envPath := filepath.Join(p.AppPath, ".env")

	// Backup existing .env
	if _, err := os.Stat(envPath); err == nil {
		backupPath := envPath + ".backup"
		e.RunCommandWithExitCode(ctx, "cp", envPath, backupPath)
	}

	// Write new .env
	if err := os.WriteFile(envPath, []byte(p.Content), 0644); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Str("path", envPath).Msg("Updated environment file")

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Updated %s", envPath),
	}
}

// Supervisor handlers

func (e *Executor) handleSupervisorCreate(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ProgramID string `json:"program_id"`
		Name      string `json:"name"`
		Config    string `json:"config"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Write supervisor config
	configPath := fmt.Sprintf("/etc/supervisor/conf.d/%s.conf", p.Name)
	if err := os.WriteFile(configPath, []byte(p.Config), 0644); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write config: %v", err)}
	}
	output.WriteString(fmt.Sprintf("Created config: %s\n", configPath))

	// Reread supervisor config
	out, _, err := e.RunCommandWithExitCode(ctx, "supervisorctl", "reread")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "failed to reread supervisor config"}
	}

	// Update (add new programs)
	out, _, err = e.RunCommandWithExitCode(ctx, "supervisorctl", "update")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "failed to update supervisor"}
	}

	output.WriteString(fmt.Sprintf("Program %s created and started\n", p.Name))

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

func (e *Executor) handleSupervisorUpdate(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ProgramID string `json:"program_id"`
		Name      string `json:"name"`
		Config    string `json:"config"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Write updated config
	configPath := fmt.Sprintf("/etc/supervisor/conf.d/%s.conf", p.Name)
	if err := os.WriteFile(configPath, []byte(p.Config), 0644); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write config: %v", err)}
	}
	output.WriteString(fmt.Sprintf("Updated config: %s\n", configPath))

	// Reread and update
	e.RunCommandWithExitCode(ctx, "supervisorctl", "reread")
	out, _, err := e.RunCommandWithExitCode(ctx, "supervisorctl", "update")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "failed to update supervisor"}
	}

	// Restart the program to apply changes
	out, _, _ = e.RunCommandWithExitCode(ctx, "supervisorctl", "restart", p.Name+":")
	output.WriteString(out + "\n")

	output.WriteString(fmt.Sprintf("Program %s updated\n", p.Name))

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

func (e *Executor) handleSupervisorDelete(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ProgramID string `json:"program_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Stop the program first
	out, _, _ := e.RunCommandWithExitCode(ctx, "supervisorctl", "stop", p.Name+":")
	output.WriteString(out + "\n")

	// Remove config file
	configPath := fmt.Sprintf("/etc/supervisor/conf.d/%s.conf", p.Name)
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		output.WriteString(fmt.Sprintf("Warning: failed to remove config: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("Removed config: %s\n", configPath))
	}

	// Update supervisor
	e.RunCommandWithExitCode(ctx, "supervisorctl", "reread")
	out, _, _ = e.RunCommandWithExitCode(ctx, "supervisorctl", "update")
	output.WriteString(out + "\n")

	output.WriteString(fmt.Sprintf("Program %s deleted\n", p.Name))

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

func (e *Executor) handleSupervisorStart(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ProgramID string `json:"program_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	out, exitCode, err := e.RunCommandWithExitCode(ctx, "supervisorctl", "start", p.Name+":")

	return comm.JobResult{
		Success:  err == nil,
		Output:   out,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleSupervisorStop(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ProgramID string `json:"program_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	out, exitCode, err := e.RunCommandWithExitCode(ctx, "supervisorctl", "stop", p.Name+":")

	return comm.JobResult{
		Success:  err == nil,
		Output:   out,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleSupervisorRestart(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		ProgramID string `json:"program_id"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	out, exitCode, err := e.RunCommandWithExitCode(ctx, "supervisorctl", "restart", p.Name+":")

	return comm.JobResult{
		Success:  err == nil,
		Output:   out,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

// Apache handlers (for nginx_apache hybrid mode)

func (e *Executor) handleCreateApacheVhost(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID       string `json:"app_id"`
		Domain      string `json:"domain"`
		Config      string `json:"config"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Write Apache vhost config
	configPath := fmt.Sprintf("/etc/apache2/sites-available/%s.conf", p.Domain)
	if err := os.WriteFile(configPath, []byte(p.Config), 0644); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write apache config: %v", err)}
	}
	output.WriteString(fmt.Sprintf("Created Apache config: %s\n", configPath))

	// Enable the site
	out, _, err := e.RunCommandWithExitCode(ctx, "a2ensite", p.Domain+".conf")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "failed to enable apache site"}
	}

	// Test Apache config
	out, _, err = e.RunCommandWithExitCode(ctx, "apache2ctl", "configtest")
	output.WriteString(out + "\n")
	if err != nil {
		// Disable site if config test fails
		e.RunCommandWithExitCode(ctx, "a2dissite", p.Domain+".conf")
		os.Remove(configPath)
		return comm.JobResult{Success: false, Output: output.String(), Error: "apache config test failed"}
	}

	// Reload Apache
	e.RunCommandWithExitCode(ctx, "systemctl", "reload", "apache2")
	output.WriteString("Apache reloaded\n")

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

func (e *Executor) handleUpdateApacheVhost(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID  string `json:"app_id"`
		Domain string `json:"domain"`
		Config string `json:"config"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Write updated config
	configPath := fmt.Sprintf("/etc/apache2/sites-available/%s.conf", p.Domain)
	if err := os.WriteFile(configPath, []byte(p.Config), 0644); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write apache config: %v", err)}
	}
	output.WriteString(fmt.Sprintf("Updated Apache config: %s\n", configPath))

	// Test Apache config
	out, _, err := e.RunCommandWithExitCode(ctx, "apache2ctl", "configtest")
	output.WriteString(out + "\n")
	if err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "apache config test failed"}
	}

	// Reload Apache
	e.RunCommandWithExitCode(ctx, "systemctl", "reload", "apache2")
	output.WriteString("Apache reloaded\n")

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

func (e *Executor) handleDeleteApacheVhost(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		AppID  string `json:"app_id"`
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	var output strings.Builder

	// Disable the site
	out, _, _ := e.RunCommandWithExitCode(ctx, "a2dissite", p.Domain+".conf")
	output.WriteString(out + "\n")

	// Remove config file
	configPath := fmt.Sprintf("/etc/apache2/sites-available/%s.conf", p.Domain)
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		output.WriteString(fmt.Sprintf("Warning: failed to remove config: %v\n", err))
	} else {
		output.WriteString(fmt.Sprintf("Removed config: %s\n", configPath))
	}

	// Reload Apache
	e.RunCommandWithExitCode(ctx, "systemctl", "reload", "apache2")
	output.WriteString("Apache reloaded\n")

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

// File Manager handlers

func (e *Executor) handleListDirectory(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path     string `json:"path"`
		BasePath string `json:"base_path"` // Security: only allow operations within this path
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	entries, err := os.ReadDir(p.Path)
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	type FileInfo struct {
		Name        string `json:"name"`
		IsDirectory bool   `json:"is_directory"`
		Size        int64  `json:"size"`
		ModTime     string `json:"mod_time"`
		Permissions string `json:"permissions"`
	}

	files := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:        entry.Name(),
			IsDirectory: entry.IsDir(),
			Size:        info.Size(),
			ModTime:     info.ModTime().Format("2006-01-02 15:04:05"),
			Permissions: info.Mode().String(),
		})
	}

	filesJSON, _ := json.Marshal(files)

	return comm.JobResult{
		Success: true,
		Output:  string(filesJSON),
		Data:    map[string]interface{}{"files": files},
	}
}

func (e *Executor) handleReadFile(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path      string `json:"path"`
		BasePath  string `json:"base_path"`
		MaxBytes  int64  `json:"max_bytes"` // Limit file size to read
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	// Check file size first
	info, err := os.Stat(p.Path)
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	if info.IsDir() {
		return comm.JobResult{Success: false, Error: "cannot read directory as file"}
	}

	maxBytes := p.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024 // Default 1MB limit
	}

	if info.Size() > maxBytes {
		return comm.JobResult{
			Success: false,
			Error:   fmt.Sprintf("file too large: %d bytes (max: %d)", info.Size(), maxBytes),
		}
	}

	content, err := os.ReadFile(p.Path)
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	return comm.JobResult{
		Success: true,
		Output:  string(content),
		Data: map[string]interface{}{
			"size":     info.Size(),
			"mod_time": info.ModTime().Format("2006-01-02 15:04:05"),
		},
	}
}

func (e *Executor) handleWriteFile(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path     string `json:"path"`
		BasePath string `json:"base_path"`
		Content  string `json:"content"`
		Mode     string `json:"mode"` // Optional: file mode as string e.g. "0644"
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	// Determine file mode
	mode := os.FileMode(0644)
	if p.Mode != "" {
		var modeInt int
		fmt.Sscanf(p.Mode, "%o", &modeInt)
		mode = os.FileMode(modeInt)
	}

	// Create parent directories if needed
	parentDir := filepath.Dir(p.Path)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to create parent directory: %v", err)}
	}

	// Write file
	if err := os.WriteFile(p.Path, []byte(p.Content), mode); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Str("path", p.Path).Int("size", len(p.Content)).Msg("File written")

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("File written: %s (%d bytes)", p.Path, len(p.Content)),
	}
}

func (e *Executor) handleDeleteFile(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path      string `json:"path"`
		BasePath  string `json:"base_path"`
		Recursive bool   `json:"recursive"` // For directories
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	// Prevent deleting the base path itself
	absPath, _ := filepath.Abs(p.Path)
	absBase, _ := filepath.Abs(p.BasePath)
	if absPath == absBase {
		return comm.JobResult{Success: false, Error: "cannot delete the base directory"}
	}

	var err error
	if p.Recursive {
		err = os.RemoveAll(p.Path)
	} else {
		err = os.Remove(p.Path)
	}

	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Str("path", p.Path).Bool("recursive", p.Recursive).Msg("File/directory deleted")

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Deleted: %s", p.Path),
	}
}

func (e *Executor) handleCreateDirectory(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path     string `json:"path"`
		BasePath string `json:"base_path"`
		Mode     string `json:"mode"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	mode := os.FileMode(0755)
	if p.Mode != "" {
		var modeInt int
		fmt.Sscanf(p.Mode, "%o", &modeInt)
		mode = os.FileMode(modeInt)
	}

	if err := os.MkdirAll(p.Path, mode); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Str("path", p.Path).Msg("Directory created")

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Directory created: %s", p.Path),
	}
}

func (e *Executor) handleRenameFile(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		OldPath  string `json:"old_path"`
		NewPath  string `json:"new_path"`
		BasePath string `json:"base_path"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate both paths are within base path
	if !isPathWithin(p.OldPath, p.BasePath) || !isPathWithin(p.NewPath, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	if err := os.Rename(p.OldPath, p.NewPath); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Str("from", p.OldPath).Str("to", p.NewPath).Msg("File renamed")

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Renamed: %s -> %s", p.OldPath, p.NewPath),
	}
}

func (e *Executor) handleGetFileInfo(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path     string `json:"path"`
		BasePath string `json:"base_path"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	info, err := os.Stat(p.Path)
	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	fileInfo := map[string]interface{}{
		"name":         info.Name(),
		"path":         p.Path,
		"size":         info.Size(),
		"is_directory": info.IsDir(),
		"mod_time":     info.ModTime().Format("2006-01-02 15:04:05"),
		"permissions":  info.Mode().String(),
	}

	infoJSON, _ := json.Marshal(fileInfo)

	return comm.JobResult{
		Success: true,
		Output:  string(infoJSON),
		Data:    fileInfo,
	}
}

func (e *Executor) handleChmodFile(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path      string `json:"path"`
		BasePath  string `json:"base_path"`
		Mode      string `json:"mode"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	var modeInt int
	fmt.Sscanf(p.Mode, "%o", &modeInt)
	mode := os.FileMode(modeInt)

	if p.Recursive {
		output, _, err := e.RunCommandWithExitCode(ctx, "chmod", "-R", p.Mode, p.Path)
		return comm.JobResult{
			Success: err == nil,
			Output:  output,
			Error:   errToString(err),
		}
	}

	if err := os.Chmod(p.Path, mode); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Changed permissions of %s to %s", p.Path, p.Mode),
	}
}

// Log Viewer handlers

func (e *Executor) handleListLogs(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		LogPath string `json:"log_path"` // Base directory for logs (e.g., /home/app/logs)
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	type LogFile struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		ModTime  string `json:"mod_time"`
	}

	var logs []LogFile

	// Walk through log directory
	err := filepath.Walk(p.LogPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}
		if info.IsDir() {
			return nil
		}

		// Only include common log file extensions
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".log" || ext == ".txt" || strings.HasSuffix(info.Name(), ".log.1") ||
			strings.HasSuffix(info.Name(), ".log.2") || info.Name() == "error_log" ||
			info.Name() == "access_log" {
			logs = append(logs, LogFile{
				Name:    info.Name(),
				Path:    path,
				Size:    info.Size(),
				ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
		return nil
	})

	if err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Also check common system log locations for the app
	systemLogs := []string{
		fmt.Sprintf("/var/log/nginx/%s-access.log", filepath.Base(p.LogPath)),
		fmt.Sprintf("/var/log/nginx/%s-error.log", filepath.Base(p.LogPath)),
	}

	for _, logPath := range systemLogs {
		if info, err := os.Stat(logPath); err == nil && !info.IsDir() {
			logs = append(logs, LogFile{
				Name:    filepath.Base(logPath),
				Path:    logPath,
				Size:    info.Size(),
				ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
	}

	logsJSON, _ := json.Marshal(logs)

	return comm.JobResult{
		Success: true,
		Output:  string(logsJSON),
		Data:    map[string]interface{}{"logs": logs},
	}
}

func (e *Executor) handleTailLog(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path     string `json:"path"`
		Lines    int    `json:"lines"`     // Number of lines to tail (default 100)
		Follow   bool   `json:"follow"`    // Not used in sync mode, but for future SSE support
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	lines := p.Lines
	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		lines = 1000 // Max 1000 lines
	}

	// Use tail command for efficiency
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "tail", "-n", fmt.Sprintf("%d", lines), p.Path)

	return comm.JobResult{
		Success:  err == nil,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleSearchLog(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path    string `json:"path"`
		Pattern string `json:"pattern"`
		Lines   int    `json:"lines"` // Max lines to return
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	lines := p.Lines
	if lines <= 0 {
		lines = 100
	}
	if lines > 500 {
		lines = 500
	}

	// Use grep for searching
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "grep", "-n", "-m", fmt.Sprintf("%d", lines), p.Pattern, p.Path)

	// grep returns exit code 1 when no matches found - this is not an error
	if exitCode == 1 && output == "" {
		return comm.JobResult{
			Success: true,
			Output:  "No matches found",
		}
	}

	return comm.JobResult{
		Success:  err == nil || exitCode == 1,
		Output:   output,
		Error:    errToString(err),
		ExitCode: exitCode,
	}
}

func (e *Executor) handleClearLog(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path     string `json:"path"`
		BasePath string `json:"base_path"` // Security: only allow operations within this path
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Security: validate path is within base path
	if p.BasePath != "" && !isPathWithin(p.Path, p.BasePath) {
		return comm.JobResult{Success: false, Error: "access denied: path outside allowed directory"}
	}

	// Truncate the log file instead of deleting it
	if err := os.Truncate(p.Path, 0); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Str("path", p.Path).Msg("Log file cleared")

	return comm.JobResult{
		Success: true,
		Output:  fmt.Sprintf("Log file cleared: %s", p.Path),
	}
}

func (e *Executor) handleDownloadLog(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Path       string `json:"path"`
		OutputPath string `json:"output_path"` // Where to save the compressed log
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Default output path
	outputPath := p.OutputPath
	if outputPath == "" {
		outputPath = p.Path + ".gz"
	}

	// Compress the log file
	output, exitCode, err := e.RunCommandWithExitCode(ctx, "gzip", "-c", p.Path)
	if err != nil {
		return comm.JobResult{
			Success:  false,
			Output:   output,
			Error:    err.Error(),
			ExitCode: exitCode,
		}
	}

	// Write compressed content
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	// Get file size
	info, _ := os.Stat(outputPath)
	var size int64
	if info != nil {
		size = info.Size()
	}

	return comm.JobResult{
		Success: true,
		Output:  outputPath,
		Data: map[string]interface{}{
			"path":       outputPath,
			"size_bytes": size,
		},
	}
}

// Helper function to check if a path is within a base path (prevent path traversal)
func isPathWithin(path, basePath string) bool {
	if basePath == "" {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}

	// Clean and compare paths
	absPath = filepath.Clean(absPath)
	absBase = filepath.Clean(absBase)

	// Path must start with base path
	if !strings.HasPrefix(absPath, absBase) {
		return false
	}

	// Ensure it's not just a prefix match (e.g., /home/user vs /home/username)
	if len(absPath) > len(absBase) && absPath[len(absBase)] != filepath.Separator {
		return false
	}

	return true
}

// handleCheckServices checks the status of multiple services
func (e *Executor) handleCheckServices(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		Services []string `json:"services"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Strs("services", p.Services).Msg("Checking services status")

	results := make(map[string]interface{})
	var output strings.Builder

	for _, service := range p.Services {
		serviceName := getSystemdServiceName(service, "")
		out, _, err := e.RunCommandWithExitCode(ctx, "systemctl", "is-active", serviceName)
		status := strings.TrimSpace(out)
		isRunning := err == nil && status == "active"

		results[service] = map[string]interface{}{
			"running": isRunning,
			"status":  status,
		}

		icon := "✓"
		if !isRunning {
			icon = "✗"
		}
		output.WriteString(fmt.Sprintf("%s %s: %s\n", icon, service, status))
	}

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
		Data:    results,
	}
}

// handleFixPermissions fixes common permission issues on the server
func (e *Executor) handleFixPermissions(ctx context.Context, payload json.RawMessage) comm.JobResult {
	log.Info().Msg("Fixing server permissions")

	var output strings.Builder

	// Fix /home/sitekit permissions for nginx access
	paths := []string{
		"/home/sitekit",
		"/home/sitekit/web",
	}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				output.WriteString(fmt.Sprintf("Skipped %s (does not exist)\n", path))
				continue
			}
			output.WriteString(fmt.Sprintf("Error checking %s: %v\n", path, err))
			continue
		}

		mode := info.Mode().Perm()
		if mode&0005 != 0005 {
			newMode := mode | 0005 // Add read+execute for others
			if err := os.Chmod(path, newMode); err != nil {
				output.WriteString(fmt.Sprintf("Failed to fix %s: %v\n", path, err))
			} else {
				output.WriteString(fmt.Sprintf("Fixed %s: %o -> %o\n", path, mode, newMode))
			}
		} else {
			output.WriteString(fmt.Sprintf("OK %s: %o (already correct)\n", path, mode))
		}
	}

	output.WriteString("\nPermissions fixed successfully. SSL certificates should now work.\n")

	return comm.JobResult{
		Success: true,
		Output:  output.String(),
	}
}

// fixWebrootPermissions ensures nginx can traverse to the webroot to serve ACME challenges
// This fixes the common issue where /home/sitekit has 750 permissions but nginx runs as www-data
func (e *Executor) fixWebrootPermissions(webroot string) error {
	// Walk up the directory tree and ensure each directory has at least 755 permissions
	// so nginx (www-data) can traverse to the webroot
	parts := strings.Split(filepath.Clean(webroot), string(filepath.Separator))
	currentPath := "/"

	for _, part := range parts {
		if part == "" {
			continue
		}
		currentPath = filepath.Join(currentPath, part)

		info, err := os.Stat(currentPath)
		if err != nil {
			continue // Skip if doesn't exist yet
		}

		// Check if world-readable (others have read+execute)
		mode := info.Mode().Perm()
		if mode&0005 != 0005 {
			// Directory is not world-traversable, fix it
			newMode := mode | 0005 // Add read+execute for others
			log.Info().
				Str("path", currentPath).
				Str("old_mode", fmt.Sprintf("%o", mode)).
				Str("new_mode", fmt.Sprintf("%o", newMode)).
				Msg("Fixing directory permissions for nginx access")

			if err := os.Chmod(currentPath, newMode); err != nil {
				log.Warn().Err(err).Str("path", currentPath).Msg("Failed to fix permissions")
				// Continue anyway, might work with group permissions
			}
		}
	}

	return nil
}

// getCertbotError extracts a meaningful error message from certbot output
func (e *Executor) getCertbotError(output string) string {
	// Look for common certbot error patterns
	lines := strings.Split(output, "\n")

	// Priority 1: Look for "Detail:" line from ACME error
	for _, line := range lines {
		if strings.Contains(line, "Detail:") {
			// Extract just the detail part
			if idx := strings.Index(line, "Detail:"); idx != -1 {
				detail := strings.TrimSpace(line[idx+7:])
				if detail != "" {
					return detail
				}
			}
		}
	}

	// Priority 2: Look for "IMPORTANT NOTES:" section
	for i, line := range lines {
		if strings.Contains(line, "IMPORTANT NOTES:") && i+1 < len(lines) {
			// Return next non-empty line
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				note := strings.TrimSpace(lines[j])
				if note != "" && !strings.HasPrefix(note, "-") {
					return note
				}
			}
		}
	}

	// Priority 3: Look for specific error messages
	errorPatterns := []string{
		"DNS problem",
		"Connection refused",
		"Invalid response",
		"unauthorized",
		"Timeout",
		"rate limit",
		"too many certificates",
	}

	for _, line := range lines {
		for _, pattern := range errorPatterns {
			if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
				return strings.TrimSpace(line)
			}
		}
	}

	// Priority 4: Return last non-empty line as fallback
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !strings.HasPrefix(line, "-") {
			return line
		}
	}

	return ""
}
