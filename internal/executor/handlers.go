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

	// Create directory structure
	dirs := []string{
		p.RootPath,
		filepath.Join(p.RootPath, "releases"),
		filepath.Join(p.RootPath, "shared"),
		filepath.Join(p.RootPath, "logs"),
		filepath.Dir(p.PublicPath),
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
		fpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.PhpVersion, p.Username)
		if err := os.WriteFile(fpmPath, []byte(p.FpmConfig), 0644); err != nil {
			return comm.JobResult{Success: false, Error: fmt.Sprintf("failed to write fpm config: %v", err)}
		}
		output.WriteString("PHP-FPM pool config installed\n")

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
		AppID       string `json:"app_id"`
		Domain      string `json:"domain"`
		PhpVersion  string `json:"php_version"`
		NginxConfig string `json:"nginx_config"`
		FpmConfig   string `json:"fpm_config"`
		Username    string `json:"username"`
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

	// Update PHP-FPM config if provided
	if p.FpmConfig != "" {
		fpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.PhpVersion, p.Username)
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
		fpmPath := fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", p.PhpVersion, p.Username)
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
		CertID    string   `json:"cert_id"`
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
		return comm.JobResult{
			Success:  false,
			Output:   output,
			Error:    err.Error(),
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
	sslDir := fmt.Sprintf("/etc/ssl/hostman/%s", p.Domain)
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
		out, _, err := e.RunCommandWithExitCode(ctx, "mysql", "-e", createDB)
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
			out, _, err = e.RunCommandWithExitCode(ctx, "mysql", "-e", createUser)
			output.WriteString(out + "\n")
			if err != nil {
				return comm.JobResult{Success: false, Output: output.String(), Error: err.Error()}
			}

			grant := fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s'; FLUSH PRIVILEGES;", p.DatabaseName, p.Username, host)
			out, _, err = e.RunCommandWithExitCode(ctx, "mysql", "-e", grant)
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
			out, _, _ := e.RunCommandWithExitCode(ctx, "mysql", "-e", dropUser)
			output.WriteString(out + "\n")
		}

		// Drop database
		dropDB := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", p.DatabaseName)
		out, _, err := e.RunCommandWithExitCode(ctx, "mysql", "-e", dropDB)
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
	crontab.WriteString("# Managed by Hostman - Do not edit directly\n")
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
		keyPath := filepath.Join(os.TempDir(), fmt.Sprintf("hostman-deploy-%s", p.DeploymentID))
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
		scriptPath := filepath.Join(releaseDir, ".hostman-deploy.sh")
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

	// Create temp symlink
	os.Remove(tempLink)
	if err := os.Symlink(releaseDir, tempLink); err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to create symlink: " + err.Error()}
	}

	// Atomic rename
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
		cmd = fmt.Sprintf("mysqlcheck --optimize %s", p.DBName)
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
