package agent

import (
	"context"
	"sync"
	"time"

	"github.com/hostman/hostman-agent/internal/comm"
	"github.com/hostman/hostman-agent/internal/executor"
	"github.com/hostman/hostman-agent/internal/health"
	"github.com/rs/zerolog/log"
)

type Agent struct {
	cfg      *Config
	client   *comm.Client
	executor *executor.Executor
	wg       sync.WaitGroup
}

func New(cfg *Config) *Agent {
	return &Agent{
		cfg:      cfg,
		client:   comm.NewClient(cfg.SaasURL, cfg.AgentToken),
		executor: executor.NewExecutor(5 * time.Minute),
	}
}

func (a *Agent) Run(ctx context.Context) error {
	// Register handlers
	a.executor.RegisterHandlers()

	// Start job processor
	a.wg.Add(1)
	go a.jobLoop(ctx)

	// Start heartbeat loop
	a.wg.Add(1)
	go a.heartbeatLoop(ctx)

	// Wait for shutdown
	<-ctx.Done()
	log.Info().Msg("Shutting down agent...")

	a.wg.Wait()
	return nil
}

func (a *Agent) jobLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.processJobs(ctx)
		}
	}
}

func (a *Agent) processJobs(ctx context.Context) {
	jobs, err := a.client.FetchJobs(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch jobs")
		return
	}

	if len(jobs) == 0 {
		return
	}

	log.Info().Int("count", len(jobs)).Msg("Processing jobs")

	for _, job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			a.executeJob(ctx, job)
		}
	}
}

func (a *Agent) executeJob(ctx context.Context, job comm.Job) {
	log.Info().
		Str("job_id", job.ID).
		Str("type", job.Type).
		Msg("Executing job")

	result := a.executor.Execute(ctx, job.Type, job.Payload)

	// Report result back to SaaS
	if err := a.client.ReportJobComplete(ctx, job.ID, result); err != nil {
		log.Error().
			Err(err).
			Str("job_id", job.ID).
			Msg("Failed to report job completion")
	} else {
		log.Info().
			Str("job_id", job.ID).
			Bool("success", result.Success).
			Msg("Job completed")
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()

	// Send initial heartbeat immediately
	a.sendHeartbeat(ctx)

	ticker := time.NewTicker(a.cfg.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	stats, err := health.CollectStats()
	if err != nil {
		log.Error().Err(err).Msg("Failed to collect stats")
		return
	}

	services := health.CollectServiceStatuses()

	if err := a.client.SendHeartbeat(ctx, stats, services); err != nil {
		log.Error().Err(err).Msg("Failed to send heartbeat")
	} else {
		log.Debug().
			Float64("cpu", stats.CPUPercent).
			Float64("mem", stats.MemoryPercent).
			Int("services", len(services)).
			Msg("Heartbeat sent")
	}
}
