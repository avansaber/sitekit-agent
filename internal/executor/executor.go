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

	"github.com/hostman/hostman-agent/internal/comm"
	"github.com/rs/zerolog/log"
)

var ErrTimeout = errors.New("command timed out")

type JobHandler func(ctx context.Context, payload json.RawMessage) comm.JobResult

type Executor struct {
	defaultTimeout time.Duration
	handlers       map[string]JobHandler
}

func NewExecutor(timeout time.Duration) *Executor {
	return &Executor{
		defaultTimeout: timeout,
		handlers:       make(map[string]JobHandler),
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

	// Deployment
	e.Register("deploy", e.handleDeploy)

	// Generic command (use with caution)
	e.Register("run_script", e.handleRunScript)

	log.Info().Int("handlers", len(e.handlers)).Msg("Registered job handlers")
}
