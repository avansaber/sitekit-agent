package agent

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

type Config struct {
	SaasURL       string        `mapstructure:"saas_url"`
	AgentToken    string        `mapstructure:"agent_token"`
	ServerID      string        `mapstructure:"server_id"`
	WebSocketURL  string        `mapstructure:"websocket_url"`
	PollInterval  time.Duration `mapstructure:"poll_interval"`
	StatsInterval time.Duration `mapstructure:"stats_interval"`
	LogLevel      string        `mapstructure:"log_level"`

	// Database credentials for agent operations
	MySQL      DatabaseConfig `mapstructure:"mysql"`
	PostgreSQL DatabaseConfig `mapstructure:"postgresql"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("agent")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/opt/hostman")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")

	// Defaults
	viper.SetDefault("poll_interval", "5s")
	viper.SetDefault("stats_interval", "60s")
	viper.SetDefault("log_level", "info")

	// Database defaults
	viper.SetDefault("mysql.host", "localhost")
	viper.SetDefault("mysql.port", 3306)
	viper.SetDefault("mysql.user", "sitekit")
	viper.SetDefault("postgresql.host", "localhost")
	viper.SetDefault("postgresql.port", 5432)
	viper.SetDefault("postgresql.user", "sitekit")

	// Environment variable overrides
	viper.SetEnvPrefix("HOSTMAN")
	viper.AutomaticEnv()

	// Allow env vars for sensitive data
	if token := os.Getenv("HOSTMAN_AGENT_TOKEN"); token != "" {
		viper.Set("agent_token", token)
	}
	if saasURL := os.Getenv("HOSTMAN_SAAS_URL"); saasURL != "" {
		viper.Set("saas_url", saasURL)
	}
	if serverID := os.Getenv("HOSTMAN_SERVER_ID"); serverID != "" {
		viper.Set("server_id", serverID)
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
		// Config file not found is OK if env vars are set
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate required fields
	if cfg.AgentToken == "" {
		return nil, fmt.Errorf("agent_token is required")
	}
	if cfg.SaasURL == "" {
		return nil, fmt.Errorf("saas_url is required")
	}

	return &cfg, nil
}
