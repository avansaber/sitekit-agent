package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/avansaber/sitekit-agent/internal/comm"
	"github.com/rs/zerolog/log"
)

// Provisioning handlers for software installation
// Each handler is idempotent - safe to retry

// handleProvisionSystem handles system updates and security configuration
func (e *Executor) handleProvisionSystem(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID   int64    `json:"step_id"`
		Includes []string `json:"includes"` // apt_update, fail2ban, ufw
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning system")
	var output strings.Builder

	// Update package lists
	output.WriteString("=== Updating package lists ===\n")
	updateOut, _, updateErr := e.RunCommandWithExitCode(ctx, "apt-get", "update", "-qq")
	output.WriteString(updateOut)
	if updateErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to update package lists: " + updateErr.Error()}
	}

	// Install basic tools
	output.WriteString("\n=== Installing base tools ===\n")
	basePackages := []string{"git", "unzip", "zip", "acl", "software-properties-common", "gnupg2"}
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", append([]string{"install", "-y", "-qq"}, basePackages...)...)
	output.WriteString(installOut)
	if installErr != nil {
		log.Warn().Err(installErr).Msg("Some base packages may have failed")
	}

	// Install and configure fail2ban
	output.WriteString("\n=== Installing fail2ban ===\n")
	f2bOut, _, f2bErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "fail2ban")
	output.WriteString(f2bOut)
	if f2bErr == nil {
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "fail2ban")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "fail2ban")
		output.WriteString("fail2ban enabled and started\n")
	}

	// Configure UFW firewall
	output.WriteString("\n=== Configuring firewall ===\n")
	ufwOut, _, ufwErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "ufw")
	output.WriteString(ufwOut)
	if ufwErr == nil {
		e.RunCommandWithExitCode(ctx, "ufw", "default", "deny", "incoming")
		e.RunCommandWithExitCode(ctx, "ufw", "default", "allow", "outgoing")
		e.RunCommandWithExitCode(ctx, "ufw", "allow", "ssh")
		e.RunCommandWithExitCode(ctx, "ufw", "allow", "http")
		e.RunCommandWithExitCode(ctx, "ufw", "allow", "https")
		e.RunCommandWithExitCode(ctx, "ufw", "--force", "enable")
		output.WriteString("UFW firewall configured (SSH, HTTP, HTTPS allowed)\n")
	}

	// Configure automatic security updates
	output.WriteString("\n=== Configuring automatic security updates ===\n")
	e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "unattended-upgrades", "apt-listchanges")

	autoUpgradesConf := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`
	os.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", []byte(autoUpgradesConf), 0644)
	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "unattended-upgrades")
	output.WriteString("Automatic security updates configured\n")

	// Create swap if needed
	output.WriteString("\n=== Configuring swap ===\n")
	if _, err := os.Stat("/swapfile"); os.IsNotExist(err) {
		e.RunCommandWithExitCode(ctx, "fallocate", "-l", "1G", "/swapfile")
		e.RunCommandWithExitCode(ctx, "chmod", "600", "/swapfile")
		e.RunCommandWithExitCode(ctx, "mkswap", "/swapfile")
		e.RunCommandWithExitCode(ctx, "swapon", "/swapfile")
		// Add to fstab
		f, _ := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
		if f != nil {
			f.WriteString("/swapfile none swap sw 0 0\n")
			f.Close()
		}
		output.WriteString("1GB swap file created\n")
	} else {
		output.WriteString("Swap already exists\n")
	}

	output.WriteString("\n=== System provisioning complete ===\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionNginx installs and configures Nginx
func (e *Executor) handleProvisionNginx(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID int64 `json:"step_id"`
	}
	json.Unmarshal(payload, &p)

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning Nginx")
	var output strings.Builder

	// Check if properly installed (binary AND config must exist)
	binaryExists := false
	configExists := false

	if _, err := os.Stat("/usr/sbin/nginx"); err == nil {
		binaryExists = true
	}
	if _, err := os.Stat("/etc/nginx/nginx.conf"); err == nil {
		configExists = true
	}

	if binaryExists && configExists {
		output.WriteString("Nginx is already installed\n")
		// Ensure it's running
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "nginx")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "nginx")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// If binary exists but config doesn't, reinstall
	if binaryExists && !configExists {
		output.WriteString("Nginx binary exists but config missing, reinstalling...\n")
		e.RunCommandWithExitCode(ctx, "apt-get", "purge", "-y", "nginx", "nginx-common")
		e.RunCommandWithExitCode(ctx, "rm", "-rf", "/etc/nginx")
	}

	output.WriteString("=== Installing Nginx ===\n")
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "nginx")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Nginx: " + installErr.Error()}
	}

	// Enable and start
	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "nginx")
	e.RunCommandWithExitCode(ctx, "systemctl", "start", "nginx")

	// Create directories
	os.MkdirAll("/var/www", 0755)

	// Remove default site
	os.Remove("/etc/nginx/sites-enabled/default")

	// Add security configuration
	securityConf := `# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;

# Hide Nginx version
server_tokens off;

# Limit request size
client_max_body_size 64M;
`
	os.WriteFile("/etc/nginx/conf.d/security.conf", []byte(securityConf), 0644)
	e.RunCommandWithExitCode(ctx, "systemctl", "reload", "nginx")

	output.WriteString("Nginx installed and configured\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionApache installs and configures Apache
func (e *Executor) handleProvisionApache(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID int64 `json:"step_id"`
	}
	json.Unmarshal(payload, &p)

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning Apache")
	var output strings.Builder

	// Check if properly installed (binary AND config directory must exist)
	binaryExists := false
	configExists := false

	if _, err := os.Stat("/usr/sbin/apache2"); err == nil {
		binaryExists = true
	}
	if _, err := os.Stat("/etc/apache2/apache2.conf"); err == nil {
		configExists = true
	}

	if binaryExists && configExists {
		output.WriteString("Apache is already installed\n")
		// Apache is disabled by default - user must start manually
		e.RunCommandWithExitCode(ctx, "systemctl", "disable", "apache2")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// If binary exists but config doesn't, reinstall
	if binaryExists && !configExists {
		output.WriteString("Apache binary exists but config missing, reinstalling...\n")
		e.RunCommandWithExitCode(ctx, "apt-get", "purge", "-y", "apache2", "apache2-bin", "apache2-utils", "libapache2-mod-fcgid")
		e.RunCommandWithExitCode(ctx, "rm", "-rf", "/etc/apache2")
	}

	output.WriteString("=== Installing Apache ===\n")
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "apache2", "libapache2-mod-fcgid")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Apache: " + installErr.Error()}
	}

	// Enable required modules
	e.RunCommandWithExitCode(ctx, "a2enmod", "rewrite")
	e.RunCommandWithExitCode(ctx, "a2enmod", "ssl")
	e.RunCommandWithExitCode(ctx, "a2enmod", "headers")
	e.RunCommandWithExitCode(ctx, "a2enmod", "proxy")
	e.RunCommandWithExitCode(ctx, "a2enmod", "proxy_fcgi")
	e.RunCommandWithExitCode(ctx, "a2enmod", "fcgid")

	// Create sites directories
	os.MkdirAll("/etc/apache2/sites-available", 0755)
	os.MkdirAll("/etc/apache2/sites-enabled", 0755)

	// Remove default site
	os.Remove("/etc/apache2/sites-enabled/000-default.conf")

	// Apache is disabled by default - user must start manually
	// This prevents port conflicts with Nginx
	e.RunCommandWithExitCode(ctx, "systemctl", "stop", "apache2")
	e.RunCommandWithExitCode(ctx, "systemctl", "disable", "apache2")

	output.WriteString("Apache installed (disabled by default - start manually when needed)\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionPHP installs a specific PHP version
func (e *Executor) handleProvisionPHP(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID  int64  `json:"step_id"`
		Version string `json:"version"` // e.g., "8.3"
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	if p.Version == "" {
		p.Version = "8.3"
	}

	log.Info().Int64("step_id", p.StepID).Str("version", p.Version).Msg("Provisioning PHP")
	var output strings.Builder

	// Check if already installed
	fpmService := fmt.Sprintf("php%s-fpm", p.Version)
	checkCmd := fmt.Sprintf("/usr/sbin/php-fpm%s", p.Version)
	if _, err := os.Stat(checkCmd); err == nil {
		output.WriteString(fmt.Sprintf("PHP %s is already installed\n", p.Version))
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", fpmService)
		e.RunCommandWithExitCode(ctx, "systemctl", "start", fpmService)
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// Add PHP repository
	output.WriteString("=== Adding PHP repository ===\n")
	e.RunCommandWithExitCode(ctx, "add-apt-repository", "-y", "ppa:ondrej/php")
	e.RunCommandWithExitCode(ctx, "apt-get", "update", "-qq")

	// Install PHP and extensions
	output.WriteString(fmt.Sprintf("=== Installing PHP %s ===\n", p.Version))
	packages := []string{
		fmt.Sprintf("php%s-fpm", p.Version),
		fmt.Sprintf("php%s-cli", p.Version),
		fmt.Sprintf("php%s-common", p.Version),
		fmt.Sprintf("php%s-mysql", p.Version),
		fmt.Sprintf("php%s-pgsql", p.Version),
		fmt.Sprintf("php%s-sqlite3", p.Version),
		fmt.Sprintf("php%s-xml", p.Version),
		fmt.Sprintf("php%s-curl", p.Version),
		fmt.Sprintf("php%s-mbstring", p.Version),
		fmt.Sprintf("php%s-zip", p.Version),
		fmt.Sprintf("php%s-gd", p.Version),
		fmt.Sprintf("php%s-bcmath", p.Version),
		fmt.Sprintf("php%s-intl", p.Version),
		fmt.Sprintf("php%s-redis", p.Version),
	}

	args := append([]string{"install", "-y", "-qq"}, packages...)
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", args...)
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: fmt.Sprintf("Failed to install PHP %s: %s", p.Version, installErr.Error())}
	}

	// Try to install imagick (may fail on some systems)
	e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", fmt.Sprintf("php%s-imagick", p.Version))

	// Create log directory
	logDir := fmt.Sprintf("/var/log/php%s-fpm", p.Version)
	os.MkdirAll(logDir, 0755)
	e.RunCommandWithExitCode(ctx, "chown", "www-data:www-data", logDir)

	// Enable and start
	e.RunCommandWithExitCode(ctx, "systemctl", "enable", fpmService)
	e.RunCommandWithExitCode(ctx, "systemctl", "start", fpmService)

	output.WriteString(fmt.Sprintf("PHP %s installed and running\n", p.Version))
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionMariaDB installs and configures MariaDB
func (e *Executor) handleProvisionMariaDB(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID        int64  `json:"step_id"`
		Version       string `json:"version"`
		StartsDisabled bool  `json:"starts_disabled"`
	}
	json.Unmarshal(payload, &p)

	if p.Version == "" {
		p.Version = "11.4" // Default LTS version
	}

	log.Info().Int64("step_id", p.StepID).Str("version", p.Version).Msg("Provisioning MariaDB")
	var output strings.Builder

	// Check if MariaDB is properly installed (binary AND data directory must exist)
	mariadbBinaryExists := false
	mariadbDataExists := false

	if _, err := os.Stat("/usr/bin/mariadb"); err == nil {
		mariadbBinaryExists = true
	} else if _, err := os.Stat("/usr/bin/mysql"); err == nil {
		// Check if the mysql binary is actually MariaDB
		versionOut, _, _ := e.RunCommandWithExitCode(ctx, "mysql", "--version")
		if strings.Contains(strings.ToLower(versionOut), "mariadb") {
			mariadbBinaryExists = true
		}
	}

	// Check if data directory exists and has data
	if _, err := os.Stat("/var/lib/mysql/mysql"); err == nil {
		mariadbDataExists = true
	}

	if mariadbBinaryExists && mariadbDataExists {
		output.WriteString("MariaDB is already installed\n")
		// Stop MySQL if it's running (to avoid port conflict)
		if e.isServiceActive(ctx, "mysql") {
			output.WriteString("Stopping MySQL to start MariaDB\n")
			e.RunCommandWithExitCode(ctx, "systemctl", "stop", "mysql")
			e.RunCommandWithExitCode(ctx, "systemctl", "disable", "mysql")
		}
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "mariadb")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "mariadb")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// If binary exists but data doesn't, we need to reinstall
	if mariadbBinaryExists && !mariadbDataExists {
		output.WriteString("MariaDB binary exists but data directory missing, reinstalling...\n")
		e.RunCommandWithExitCode(ctx, "apt-get", "purge", "-y", "mariadb-server", "mariadb-client")
		e.RunCommandWithExitCode(ctx, "rm", "-rf", "/var/lib/mysql", "/etc/mysql")
	}

	// Stop MySQL if it's running before installing MariaDB
	if e.isServiceActive(ctx, "mysql") {
		output.WriteString("Stopping MySQL before installing MariaDB\n")
		e.RunCommandWithExitCode(ctx, "systemctl", "stop", "mysql")
		e.RunCommandWithExitCode(ctx, "systemctl", "disable", "mysql")
	}

	output.WriteString("=== Adding MariaDB official repository ===\n")
	// Add MariaDB official repository for latest versions
	e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "curl", "gnupg")

	// Add MariaDB signing key
	e.RunCommandWithExitCode(ctx, "bash", "-c", "curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc | gpg --dearmor -o /usr/share/keyrings/mariadb-keyring.gpg")

	// Add MariaDB repository
	osCodename, _, _ := e.RunCommandWithExitCode(ctx, "bash", "-c", "lsb_release -cs")
	osCodename = strings.TrimSpace(osCodename)
	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/mariadb-keyring.gpg] https://dlm.mariadb.com/repo/mariadb-server/%s/repo/ubuntu %s main", p.Version, osCodename)
	os.WriteFile("/etc/apt/sources.list.d/mariadb.list", []byte(repoLine+"\n"), 0644)

	e.RunCommandWithExitCode(ctx, "apt-get", "update", "-qq")

	output.WriteString(fmt.Sprintf("=== Installing MariaDB %s ===\n", p.Version))
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "mariadb-server", "mariadb-client")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install MariaDB: " + installErr.Error()}
	}

	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "mariadb")
	e.RunCommandWithExitCode(ctx, "systemctl", "start", "mariadb")

	// Check if credentials already exist
	configDir := "/opt/sitekit/config"
	os.MkdirAll(configDir, 0755)

	if _, err := os.Stat(configDir + "/.mysql_root"); err == nil {
		output.WriteString("MariaDB credentials already configured\n")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// Generate and set root password
	rootPass, _, _ := e.RunCommandWithExitCode(ctx, "openssl", "rand", "-base64", "24")
	rootPass = strings.TrimSpace(rootPass)

	// Try to secure the installation
	e.RunCommandWithExitCode(ctx, "mysql", "-e", fmt.Sprintf("ALTER USER 'root'@'localhost' IDENTIFIED BY '%s';", rootPass))
	e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "DELETE FROM mysql.user WHERE User='';")
	e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "DROP DATABASE IF EXISTS test;")
	e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "FLUSH PRIVILEGES;")

	os.WriteFile(configDir+"/.mysql_root", []byte(rootPass), 0600)

	// Create sitekit system user
	sitekitPass, _, _ := e.RunCommandWithExitCode(ctx, "openssl", "rand", "-base64", "24")
	sitekitPass = strings.TrimSpace(sitekitPass)

	e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e",
		fmt.Sprintf("CREATE USER IF NOT EXISTS 'sitekit'@'localhost' IDENTIFIED BY '%s';", sitekitPass))
	e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e",
		"GRANT ALL PRIVILEGES ON *.* TO 'sitekit'@'localhost' WITH GRANT OPTION;")
	e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "FLUSH PRIVILEGES;")

	os.WriteFile(configDir+"/.mysql_sitekit", []byte(sitekitPass), 0600)

	// Update agent config with database credentials
	e.updateAgentConfigWithMySQL(sitekitPass)

	output.WriteString("MariaDB installed and secured\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionMySQL installs and configures MySQL
// If MariaDB is running, MySQL is installed but kept stopped (user can switch via UI)
func (e *Executor) handleProvisionMySQL(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID         int64  `json:"step_id"`
		Version        string `json:"version"`
		StartsDisabled bool   `json:"starts_disabled"`
	}
	json.Unmarshal(payload, &p)

	if p.Version == "" {
		p.Version = "8.4" // Default to LTS
	}

	log.Info().Int64("step_id", p.StepID).Str("version", p.Version).Msg("Provisioning MySQL")
	var output strings.Builder

	// Check if MySQL is already installed
	mysqlInstalled := false
	if _, err := os.Stat("/usr/bin/mysql"); err == nil {
		versionOut, _, _ := e.RunCommandWithExitCode(ctx, "mysql", "--version")
		if !strings.Contains(strings.ToLower(versionOut), "mariadb") {
			mysqlInstalled = true
		}
	}

	// Check if MariaDB is currently active
	mariadbActive := e.isServiceActive(ctx, "mariadb")

	if mysqlInstalled {
		output.WriteString("MySQL is already installed\n")
		if mariadbActive || p.StartsDisabled {
			// MariaDB is running or we're asked to keep MySQL disabled
			output.WriteString("MariaDB is active - keeping MySQL stopped\n")
			e.RunCommandWithExitCode(ctx, "systemctl", "stop", "mysql")
			e.RunCommandWithExitCode(ctx, "systemctl", "disable", "mysql")
			output.WriteString("MySQL installed but disabled (activate via SiteKit UI)\n")
		} else {
			e.RunCommandWithExitCode(ctx, "systemctl", "enable", "mysql")
			e.RunCommandWithExitCode(ctx, "systemctl", "start", "mysql")
		}
		return comm.JobResult{Success: true, Output: output.String()}
	}

	output.WriteString("=== Installing MySQL ===\n")

	// Add MySQL APT repository for latest version
	e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "gnupg", "wget")

	// Download and add MySQL APT config (latest version)
	e.RunCommandWithExitCode(ctx, "bash", "-c", "wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.30-1_all.deb -O /tmp/mysql-apt-config.deb")
	e.RunCommandWithExitCode(ctx, "bash", "-c", "DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/mysql-apt-config.deb")
	e.RunCommandWithExitCode(ctx, "apt-get", "update", "-qq")

	// Install MySQL server
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mysql-server")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install MySQL: " + installErr.Error()}
	}

	// Decide whether to start MySQL based on MariaDB status
	if mariadbActive || p.StartsDisabled {
		// MariaDB is running - keep MySQL stopped to avoid port conflict
		output.WriteString("MariaDB is active - keeping MySQL stopped\n")
		e.RunCommandWithExitCode(ctx, "systemctl", "stop", "mysql")
		e.RunCommandWithExitCode(ctx, "systemctl", "disable", "mysql")
	} else {
		// No MariaDB running - MySQL can be active
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "mysql")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "mysql")
	}

	// Check if credentials already exist
	configDir := "/opt/sitekit/config"
	os.MkdirAll(configDir, 0755)

	// For credential setup, we need MySQL running temporarily
	needsCredentialSetup := false
	if _, err := os.Stat(configDir + "/.mysql8_root"); os.IsNotExist(err) {
		needsCredentialSetup = true
	}

	if needsCredentialSetup {
		// Temporarily start MySQL for credential setup if it's not running
		wasRunning := e.isServiceActive(ctx, "mysql")
		if !wasRunning {
			// Stop MariaDB temporarily if needed
			if mariadbActive {
				e.RunCommandWithExitCode(ctx, "systemctl", "stop", "mariadb")
			}
			e.RunCommandWithExitCode(ctx, "systemctl", "start", "mysql")
		}

		// Generate and set root password
		rootPass, _, _ := e.RunCommandWithExitCode(ctx, "openssl", "rand", "-base64", "24")
		rootPass = strings.TrimSpace(rootPass)

		// Secure the installation
		e.RunCommandWithExitCode(ctx, "mysql", "-e", fmt.Sprintf("ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '%s';", rootPass))
		e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "DELETE FROM mysql.user WHERE User='';")
		e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "DROP DATABASE IF EXISTS test;")
		e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "FLUSH PRIVILEGES;")

		// Store MySQL 8.x credentials separately from MariaDB
		os.WriteFile(configDir+"/.mysql8_root", []byte(rootPass), 0600)

		// Create sitekit system user
		sitekitPass, _, _ := e.RunCommandWithExitCode(ctx, "openssl", "rand", "-base64", "24")
		sitekitPass = strings.TrimSpace(sitekitPass)

		e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e",
			fmt.Sprintf("CREATE USER IF NOT EXISTS 'sitekit'@'localhost' IDENTIFIED WITH caching_sha2_password BY '%s';", sitekitPass))
		e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e",
			"GRANT ALL PRIVILEGES ON *.* TO 'sitekit'@'localhost' WITH GRANT OPTION;")
		e.RunCommandWithExitCode(ctx, "mysql", "-u", "root", "-p"+rootPass, "-e", "FLUSH PRIVILEGES;")

		os.WriteFile(configDir+"/.mysql8_sitekit", []byte(sitekitPass), 0600)

		// Restore original state
		if !wasRunning {
			e.RunCommandWithExitCode(ctx, "systemctl", "stop", "mysql")
			e.RunCommandWithExitCode(ctx, "systemctl", "disable", "mysql")
			if mariadbActive {
				e.RunCommandWithExitCode(ctx, "systemctl", "start", "mariadb")
			}
		}
	} else {
		output.WriteString("MySQL credentials already configured\n")
	}

	if mariadbActive || p.StartsDisabled {
		output.WriteString("MySQL installed but disabled (MariaDB is default - switch via SiteKit UI)\n")
	} else {
		output.WriteString("MySQL installed and secured\n")
	}
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionPostgreSQL installs and configures PostgreSQL
func (e *Executor) handleProvisionPostgreSQL(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID  int64  `json:"step_id"`
		Version string `json:"version"`
	}
	json.Unmarshal(payload, &p)

	if p.Version == "" {
		p.Version = "17" // Latest stable
	}

	log.Info().Int64("step_id", p.StepID).Str("version", p.Version).Msg("Provisioning PostgreSQL")
	var output strings.Builder

	// Check if already installed
	if _, err := os.Stat("/usr/bin/psql"); err == nil {
		output.WriteString("PostgreSQL is already installed\n")
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "postgresql")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "postgresql")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	output.WriteString("=== Adding PostgreSQL official repository ===\n")
	// Add PostgreSQL Global Development Group (PGDG) repository
	e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "curl", "gnupg", "lsb-release")

	// Add PostgreSQL signing key
	e.RunCommandWithExitCode(ctx, "bash", "-c", "curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgresql-keyring.gpg")

	// Add PostgreSQL repository
	osCodename, _, _ := e.RunCommandWithExitCode(ctx, "bash", "-c", "lsb_release -cs")
	osCodename = strings.TrimSpace(osCodename)
	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/postgresql-keyring.gpg] https://apt.postgresql.org/pub/repos/apt %s-pgdg main", osCodename)
	os.WriteFile("/etc/apt/sources.list.d/pgdg.list", []byte(repoLine+"\n"), 0644)

	e.RunCommandWithExitCode(ctx, "apt-get", "update", "-qq")

	output.WriteString(fmt.Sprintf("=== Installing PostgreSQL %s ===\n", p.Version))
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", fmt.Sprintf("postgresql-%s", p.Version), "postgresql-contrib")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install PostgreSQL: " + installErr.Error()}
	}

	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "postgresql")
	e.RunCommandWithExitCode(ctx, "systemctl", "start", "postgresql")

	// Check if credentials already exist
	configDir := "/opt/sitekit/config"
	os.MkdirAll(configDir, 0755)

	if _, err := os.Stat(configDir + "/.pgsql_sitekit"); err == nil {
		output.WriteString("PostgreSQL credentials already configured\n")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// Create sitekit user
	sitekitPgPass, _, _ := e.RunCommandWithExitCode(ctx, "openssl", "rand", "-base64", "24")
	sitekitPgPass = strings.TrimSpace(sitekitPgPass)

	createUserSQL := fmt.Sprintf("CREATE USER sitekit WITH SUPERUSER CREATEDB CREATEROLE PASSWORD '%s';", sitekitPgPass)
	e.RunCommandWithExitCode(ctx, "sudo", "-u", "postgres", "psql", "-c", createUserSQL)

	os.WriteFile(configDir+"/.pgsql_sitekit", []byte(sitekitPgPass), 0600)

	// Update agent config with database credentials
	e.updateAgentConfigWithPostgreSQL(sitekitPgPass)

	output.WriteString("PostgreSQL installed and configured\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionRedis installs and configures Redis
func (e *Executor) handleProvisionRedis(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID int64 `json:"step_id"`
	}
	json.Unmarshal(payload, &p)

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning Redis")
	var output strings.Builder

	// Check if properly installed (binary AND config file must exist)
	binaryExists := false
	configExists := false

	if _, err := os.Stat("/usr/bin/redis-server"); err == nil {
		binaryExists = true
	}
	if _, err := os.Stat("/etc/redis/redis.conf"); err == nil {
		configExists = true
	}

	if binaryExists && configExists {
		output.WriteString("Redis is already installed\n")
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "redis-server")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "redis-server")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// If binary exists but config doesn't, reinstall
	if binaryExists && !configExists {
		output.WriteString("Redis binary exists but config missing, reinstalling...\n")
		e.RunCommandWithExitCode(ctx, "apt-get", "purge", "-y", "redis-server")
		e.RunCommandWithExitCode(ctx, "rm", "-rf", "/etc/redis", "/var/lib/redis")
	}

	output.WriteString("=== Installing Redis ===\n")
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "redis-server")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Redis: " + installErr.Error()}
	}

	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "redis-server")
	e.RunCommandWithExitCode(ctx, "systemctl", "start", "redis-server")

	output.WriteString("Redis installed and running\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionMemcached installs Memcached
func (e *Executor) handleProvisionMemcached(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID int64 `json:"step_id"`
	}
	json.Unmarshal(payload, &p)

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning Memcached")
	var output strings.Builder

	if _, err := os.Stat("/usr/bin/memcached"); err == nil {
		output.WriteString("Memcached is already installed\n")
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "memcached")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "memcached")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	output.WriteString("=== Installing Memcached ===\n")
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "memcached", "libmemcached-tools")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Memcached: " + installErr.Error()}
	}

	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "memcached")
	e.RunCommandWithExitCode(ctx, "systemctl", "start", "memcached")

	output.WriteString("Memcached installed and running\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionComposer installs Composer
func (e *Executor) handleProvisionComposer(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID int64 `json:"step_id"`
	}
	json.Unmarshal(payload, &p)

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning Composer")
	var output strings.Builder

	if _, err := os.Stat("/usr/local/bin/composer"); err == nil {
		output.WriteString("Composer is already installed\n")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	output.WriteString("=== Installing Composer ===\n")

	// Download and install Composer
	e.RunCommandWithExitCode(ctx, "bash", "-c", "curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer")

	if _, err := os.Stat("/usr/local/bin/composer"); err != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Composer"}
	}

	output.WriteString("Composer installed successfully\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionNode installs Node.js
func (e *Executor) handleProvisionNode(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID  int64  `json:"step_id"`
		Version string `json:"version"` // e.g., "20"
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return comm.JobResult{Success: false, Error: err.Error()}
	}

	if p.Version == "" {
		p.Version = "24" // Active LTS
	}

	log.Info().Int64("step_id", p.StepID).Str("version", p.Version).Msg("Provisioning Node.js")
	var output strings.Builder

	if _, err := os.Stat("/usr/bin/node"); err == nil {
		nodeVersion, _, _ := e.RunCommandWithExitCode(ctx, "node", "-v")
		output.WriteString(fmt.Sprintf("Node.js is already installed: %s\n", strings.TrimSpace(nodeVersion)))
		return comm.JobResult{Success: true, Output: output.String()}
	}

	output.WriteString(fmt.Sprintf("=== Installing Node.js %s ===\n", p.Version))

	// Add NodeSource repository
	setupScript := fmt.Sprintf("curl -fsSL https://deb.nodesource.com/setup_%s.x | bash -", p.Version)
	e.RunCommandWithExitCode(ctx, "bash", "-c", setupScript)

	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "nodejs")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Node.js: " + installErr.Error()}
	}

	// Update npm
	e.RunCommandWithExitCode(ctx, "npm", "install", "-g", "npm@latest")

	nodeVersion, _, _ := e.RunCommandWithExitCode(ctx, "node", "-v")
	output.WriteString(fmt.Sprintf("Node.js %s installed successfully\n", strings.TrimSpace(nodeVersion)))
	return comm.JobResult{Success: true, Output: output.String()}
}

// handleProvisionSupervisor installs Supervisor
func (e *Executor) handleProvisionSupervisor(ctx context.Context, payload json.RawMessage) comm.JobResult {
	var p struct {
		StepID int64 `json:"step_id"`
	}
	json.Unmarshal(payload, &p)

	log.Info().Int64("step_id", p.StepID).Msg("Provisioning Supervisor")
	var output strings.Builder

	// Check if properly installed (binary AND config file must exist)
	binaryExists := false
	configExists := false

	if _, err := os.Stat("/usr/bin/supervisord"); err == nil {
		binaryExists = true
	}
	if _, err := os.Stat("/etc/supervisor/supervisord.conf"); err == nil {
		configExists = true
	}

	if binaryExists && configExists {
		output.WriteString("Supervisor is already installed\n")
		e.RunCommandWithExitCode(ctx, "systemctl", "enable", "supervisor")
		e.RunCommandWithExitCode(ctx, "systemctl", "start", "supervisor")
		return comm.JobResult{Success: true, Output: output.String()}
	}

	// If binary exists but config doesn't, reinstall
	if binaryExists && !configExists {
		output.WriteString("Supervisor binary exists but config missing, reinstalling...\n")
		e.RunCommandWithExitCode(ctx, "apt-get", "purge", "-y", "supervisor")
		e.RunCommandWithExitCode(ctx, "rm", "-rf", "/etc/supervisor")
	}

	output.WriteString("=== Installing Supervisor ===\n")
	installOut, _, installErr := e.RunCommandWithExitCode(ctx, "apt-get", "install", "-y", "-qq", "supervisor")
	output.WriteString(installOut)
	if installErr != nil {
		return comm.JobResult{Success: false, Output: output.String(), Error: "Failed to install Supervisor: " + installErr.Error()}
	}

	e.RunCommandWithExitCode(ctx, "systemctl", "enable", "supervisor")
	e.RunCommandWithExitCode(ctx, "systemctl", "start", "supervisor")

	output.WriteString("Supervisor installed and running\n")
	return comm.JobResult{Success: true, Output: output.String()}
}

// Helper to update agent config with MySQL credentials
func (e *Executor) updateAgentConfigWithMySQL(password string) {
	configPath := "/opt/sitekit/agent.yaml"
	content, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	config := string(content)

	// Check if mysql section exists
	if !strings.Contains(config, "mysql:") {
		// Add mysql section
		mysqlConfig := fmt.Sprintf(`
mysql:
  host: "localhost"
  port: 3306
  user: "sitekit"
  password: "%s"
`, password)
		config += mysqlConfig
		os.WriteFile(configPath, []byte(config), 0600)
	}
}

// Helper to update agent config with PostgreSQL credentials
func (e *Executor) updateAgentConfigWithPostgreSQL(password string) {
	configPath := "/opt/sitekit/agent.yaml"
	content, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	config := string(content)

	// Check if postgresql section exists
	if !strings.Contains(config, "postgresql:") {
		// Add postgresql section
		pgConfig := fmt.Sprintf(`
postgresql:
  host: "localhost"
  port: 5432
  user: "sitekit"
  password: "%s"
`, password)
		config += pgConfig
		os.WriteFile(configPath, []byte(config), 0600)
	}
}

// isServiceActive checks if a systemd service is currently running
func (e *Executor) isServiceActive(ctx context.Context, serviceName string) bool {
	out, _, _ := e.RunCommandWithExitCode(ctx, "systemctl", "is-active", serviceName)
	return strings.TrimSpace(out) == "active"
}

// isServiceInstalled checks if a systemd service unit exists
func (e *Executor) isServiceInstalled(ctx context.Context, serviceName string) bool {
	_, exitCode, _ := e.RunCommandWithExitCode(ctx, "systemctl", "list-unit-files", serviceName+".service")
	return exitCode == 0
}
