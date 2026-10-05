package compat

// The kernel's management interface (ADR-IAM-001 §5.8, TDD-identity-kernel-005 1.5.0): Keycloak's own
// health and metrics, built into the image, served on the management port and not on the port that
// serves the realm. "It provides the possibility to hide endpoints like `/metrics` or `/health` from the
// outside world" (Configuring the Management Interface), so a request for them on 8080 finds nothing.

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func managementURL(t *testing.T) string {
	t.Helper()
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_MANAGEMENT_URL")), "/")
	if base == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and KEYCLOAK_MANAGEMENT_URL is empty")
		}
		t.Skip("KEYCLOAK_MANAGEMENT_URL is unset")
	}
	return base
}

func get(t *testing.T, target string) (int, string, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header.Get("Content-Type"), string(body)
}

// The three probes answer on the management port, as Keycloak's operator binds them, and metrics are
// served there in the OpenMetrics text format.
func TestHealthAndMetricsAreOnTheManagementPort(t *testing.T) {
	a := requireKeycloak(t)
	management := managementURL(t)
	for _, path := range []string{"/health/started", "/health/live", "/health/ready"} {
		if status, _, body := get(t, management+path); status != http.StatusOK || !strings.Contains(body, `"UP"`) {
			t.Errorf("%s answered %d: %s", path, status, snippet(body))
		}
	}
	status, contentType, body := get(t, management+"/metrics")
	if status != http.StatusOK || !strings.Contains(contentType, "openmetrics") {
		t.Errorf("/metrics answered %d with %q; want the OpenMetrics text: metrics are built into the image", status, contentType)
	}
	if !strings.Contains(body, "jvm_") {
		t.Errorf("/metrics carries no JVM metric: %s", snippet(body))
	}

	// Not on the port that serves the realm.
	for _, path := range []string{"/metrics", "/health/ready", "/health/live"} {
		if status, _, _ := get(t, a.base+path); status != http.StatusNotFound {
			t.Errorf("%s on the realm's port answered %d, want 404: the management endpoints are the management port's alone",
				path, status)
		}
	}
}
