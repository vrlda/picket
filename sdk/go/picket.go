// Package picket is a minimal SDK: apps report exceptions (grouped by
// fingerprint) and custom application/business events to a picket
// server, whose rules turn them into incidents.
//
// Env: PICKET_ENDPOINT (required), PICKET_TOKEN (required),
// PICKET_HOST_ID, PICKET_SERVICE, PICKET_ENVIRONMENT.
package picket

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

// Frame is one stack frame (innermost first).
type Frame struct {
	File     string `json:"file"`
	Line     uint32 `json:"line"`
	Function string `json:"function"`
}

// Client reports exceptions to the picket server.
type Client struct {
	Endpoint    string
	Token       string
	HostID      string
	Service     string
	Environment string
}

// New builds a client from env vars (HostID defaults to the OS hostname,
// Service to "app", Environment to "prod").
func New() *Client {
	host, _ := os.Hostname()
	return &Client{
		Endpoint:    strings.TrimRight(envOr("PICKET_ENDPOINT", ""), "/"),
		Token:       envOr("PICKET_TOKEN", ""),
		HostID:      envOr("PICKET_HOST_ID", host),
		Service:     envOr("PICKET_SERVICE", "app"),
		Environment: envOr("PICKET_ENVIRONMENT", "prod"),
	}
}

func envOr(name, dflt string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	// pre-rename WATCHTOWER_* names still work as a fallback
	if v := os.Getenv(strings.Replace(name, "PICKET_", "WATCHTOWER_", 1)); v != "" {
		return v
	}
	return dflt
}

type exceptionPayload struct {
	Type    string  `json:"type"`
	Message string  `json:"message"`
	Level   string  `json:"level"`
	Frames  []Frame `json:"frames"`
}

type body struct {
	HostID      string           `json:"host_id"`
	Service     string           `json:"service"`
	Environment string           `json:"environment"`
	Exception   exceptionPayload `json:"exception"`
}

// Capture reports an exception. Best-effort with one retry; never panics.
func (c *Client) Capture(level, kind, message string, frames []Frame) bool {
	if c.Endpoint == "" || c.Token == "" {
		return false
	}
	payload, err := json.Marshal(body{
		HostID:      c.HostID,
		Service:     c.Service,
		Environment: c.Environment,
		Exception: exceptionPayload{
			Type:    kind,
			Message: message,
			Level:   level,
			Frames:  frames,
		},
	})
	if err != nil {
		return false
	}
	return c.post("/v1/errors", payload)
}

// Event is a custom application/business event (POST /v1/events). Kind is
// a dotted name such as "payment.request_failed"; Attributes are
// dimensions, Measurements numbers rules can compare.
type Event struct {
	Kind         string             `json:"kind"`
	Summary      string             `json:"summary"`
	Severity     string             `json:"severity,omitempty"`
	Subject      string             `json:"subject,omitempty"`
	Source       string             `json:"source,omitempty"`
	Environment  string             `json:"environment,omitempty"`
	ID           string             `json:"id,omitempty"`
	TS           int64              `json:"ts,omitempty"`
	Attributes   map[string]any     `json:"attributes,omitempty"`
	Measurements map[string]float64 `json:"measurements,omitempty"`
}

// CaptureEvent reports a custom event; Source and Environment default to
// the client's Service and Environment. Best-effort with one retry.
func (c *Client) CaptureEvent(e Event) bool {
	if c.Endpoint == "" || c.Token == "" {
		return false
	}
	if e.Source == "" {
		e.Source = c.Service
	}
	if e.Environment == "" {
		e.Environment = c.Environment
	}
	if e.Severity == "" {
		e.Severity = "info"
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return false
	}
	return c.post("/v1/events", payload)
}

func (c *Client) post(path string, payload []byte) bool {
	url := c.Endpoint + path
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Token)
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return true
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return false // rejected: don't retry
			}
		}
		if attempt == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return false
}
