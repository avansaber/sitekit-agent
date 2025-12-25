package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sitekit/sitekit-agent/internal/agent"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Load configuration
	cfg, err := agent.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	log.Info().
		Str("saas_url", cfg.SaasURL).
		Str("server_id", cfg.ServerID).
		Msg("Starting SiteKit Sentinel Agent")

	// Create and run agent
	a := agent.New(cfg)
	if err := a.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("Agent failed")
	}

	log.Info().Msg("Agent stopped gracefully")
}
