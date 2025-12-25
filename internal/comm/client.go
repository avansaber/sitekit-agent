package comm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/avansaber/sitekit-agent/internal/health"
)

type Client struct {
	baseURL    string
	agentToken string
	httpClient *http.Client
}

type Job struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Priority  int             `json:"priority"`
	CreatedAt time.Time       `json:"created_at"`
}

type JobResult struct {
	Success  bool                   `json:"success"`
	Output   string                 `json:"output,omitempty"`
	Error    string                 `json:"error,omitempty"`
	ExitCode int                    `json:"exit_code,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

type JobsResponse struct {
	Jobs  []Job `json:"jobs"`
	Count int   `json:"count"`
}

func NewClient(baseURL, agentToken string) *Client {
	return &Client{
		baseURL:    baseURL,
		agentToken: agentToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.agentToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return c.httpClient.Do(req)
}

func (c *Client) FetchJobs(ctx context.Context) ([]Job, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/api/agent/jobs", nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var jobsResp JobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&jobsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return jobsResp.Jobs, nil
}

func (c *Client) ReportJobComplete(ctx context.Context, jobID string, result JobResult) error {
	status := "completed"
	if !result.Success {
		status = "failed"
	}

	payload := map[string]interface{}{
		"status":    status,
		"output":    result.Output,
		"error":     result.Error,
		"exit_code": result.ExitCode,
		"data":      result.Data,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/api/agent/jobs/"+jobID+"/complete", payload)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *Client) SendHeartbeat(ctx context.Context, stats *health.SystemStats, services []health.ServiceStatus, daemons []health.DaemonStatus) error {
	payload := map[string]interface{}{
		"cpu_percent":     stats.CPUPercent,
		"memory_percent":  stats.MemoryPercent,
		"disk_percent":    stats.DiskPercent,
		"load_1m":         stats.LoadAvg1,
		"load_5m":         stats.LoadAvg5,
		"load_15m":        stats.LoadAvg15,
		"os_name":         stats.OSName,
		"os_version":      stats.OSVersion,
		"cpu_count":       stats.CPUCount,
		"memory_mb":       stats.MemoryTotalMB,
		"disk_gb":         stats.DiskTotalGB,
		"services_status": services,
		"daemons_status":  daemons,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/api/agent/heartbeat", payload)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *Client) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/api/agent/config", nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return config, nil
}
