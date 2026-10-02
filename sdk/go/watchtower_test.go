package watchtower

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCapturePostsExpectedPayload(t *testing.T) {
	var gotBody body
	var gotAuth string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{
		Endpoint:    srv.URL,
		Token:       "tok",
		HostID:      "h-1",
		Service:     "api",
		Environment: "prod",
	}
	ok := c.Capture("error", "ValueError", "bad input", []Frame{{File: "app.go", Line: 42, Function: "validate"}})
	if !ok {
		t.Fatal("capture returned false")
	}
	if gotPath != "/v1/errors" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody.HostID != "h-1" || gotBody.Service != "api" {
		t.Fatalf("body host/service = %q/%q", gotBody.HostID, gotBody.Service)
	}
	if gotBody.Exception.Type != "ValueError" || gotBody.Exception.Frames[0].Line != 42 {
		t.Fatalf("exception = %+v", gotBody.Exception)
	}
}

func TestNoConfigReturnsFalse(t *testing.T) {
	c := &Client{}
	if c.Capture("error", "T", "m", nil) {
		t.Fatal("no-config capture returned true")
	}
}

func TestCaptureEventPostsCustomEvent(t *testing.T) {
	var got map[string]any
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "tok", Service: "payment-api", Environment: "production"}
	ok := c.CaptureEvent(Event{
		Kind:         "payment.request_failed",
		Summary:      "Payment request failed",
		Severity:     "warning",
		Subject:      "merchant:mer_1",
		Attributes:   map[string]any{"merchant_id": "mer_1"},
		Measurements: map[string]float64{"latency_ms": 812},
	})
	if !ok {
		t.Fatal("CaptureEvent returned false")
	}
	if gotPath != "/v1/events" {
		t.Fatalf("path = %q", gotPath)
	}
	if got["kind"] != "payment.request_failed" || got["source"] != "payment-api" || got["environment"] != "production" {
		t.Fatalf("event = %v", got)
	}
	if _, has := got["id"]; has {
		t.Fatal("empty id must be omitted")
	}
	if got["measurements"].(map[string]any)["latency_ms"] != 812.0 {
		t.Fatalf("measurements = %v", got["measurements"])
	}
}
