package analytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMetricTypes(t *testing.T) {
	types := []MetricType{
		MetricTypeCounter,
		MetricTypeGauge,
		MetricTypeHistogram,
	}

	for _, mt := range types {
		assert.NotEmpty(t, string(mt))
	}
}

func TestMetric(t *testing.T) {
	metric := Metric{
		Name:  "cpu_usage",
		Type:  MetricTypeGauge,
		Value: 75.5,
		Labels: map[string]string{
			"device": "router-01",
			"region": "us-east",
		},
		Timestamp: time.Now(),
	}

	assert.Equal(t, "cpu_usage", metric.Name)
	assert.Equal(t, MetricTypeGauge, metric.Type)
	assert.Equal(t, 75.5, metric.Value)
	assert.Equal(t, "router-01", metric.Labels["device"])
}

func TestDashboardStats(t *testing.T) {
	stats := DashboardStats{
		Devices: DeviceStats{
			Total:       100,
			Online:      80,
			Offline:     15,
			Quarantined: 3,
			Unknown:     2,
		},
		Identities: IdentityStats{
			Total:     50,
			Operators: 20,
			Devices:   25,
			Services:  5,
			Active:    45,
			Suspended: 3,
			Revoked:   2,
		},
		Capabilities: CapabilityStats{
			Active:          100,
			PendingApproval: 5,
			ExpiredToday:    10,
			RevokedToday:    2,
			IssuedToday:     15,
		},
		Policies: PolicyStats{
			Total:            10,
			Active:           8,
			EvaluationsToday: 1000,
			DenialsToday:     50,
			AllowedToday:     950,
		},
		Deployments: DeploymentStats{
			Pending:         3,
			InProgress:      2,
			CompletedToday:  10,
			FailedToday:     1,
			RolledBackToday: 0,
		},
		Audit: AuditStats{
			EventsToday:       5000,
			SecurityEvents:    100,
			FailedAuth:        25,
			AccessDenials:     50,
			ConfigChanges:     200,
			AttestationEvents: 50,
		},
		Timestamp: time.Now(),
	}

	assert.Equal(t, 100, stats.Devices.Total)
	assert.Equal(t, 80, stats.Devices.Online)
	assert.Equal(t, 50, stats.Identities.Total)
	assert.Equal(t, 100, stats.Capabilities.Active)
	assert.Equal(t, 10, stats.Policies.Total)
	assert.Equal(t, 5000, stats.Audit.EventsToday)
}

func TestDeviceStats(t *testing.T) {
	stats := DeviceStats{
		Total:       100,
		Online:      80,
		Offline:     10,
		Quarantined: 5,
		Unknown:     5,
	}

	assert.Equal(t, 100, stats.Total)
	assert.Equal(t, stats.Online+stats.Offline+stats.Quarantined+stats.Unknown, stats.Total)
}

func TestIdentityStats(t *testing.T) {
	stats := IdentityStats{
		Total:     50,
		Operators: 20,
		Devices:   25,
		Services:  5,
		Active:    45,
		Suspended: 3,
		Revoked:   2,
	}

	assert.Equal(t, 50, stats.Total)
	assert.Equal(t, stats.Operators+stats.Devices+stats.Services, stats.Total)
	assert.Equal(t, stats.Active+stats.Suspended+stats.Revoked, stats.Total)
}

func TestCapabilityStats(t *testing.T) {
	stats := CapabilityStats{
		Active:          100,
		PendingApproval: 5,
		ExpiredToday:    10,
		RevokedToday:    2,
		IssuedToday:     15,
	}

	assert.Equal(t, 100, stats.Active)
	assert.Equal(t, 15, stats.IssuedToday)
}

func TestPolicyStats(t *testing.T) {
	stats := PolicyStats{
		Total:            10,
		Active:           8,
		EvaluationsToday: 1000,
		DenialsToday:     50,
		AllowedToday:     950,
	}

	assert.Equal(t, 10, stats.Total)
	assert.Equal(t, stats.DenialsToday+stats.AllowedToday, stats.EvaluationsToday)
}

func TestDeploymentStats(t *testing.T) {
	stats := DeploymentStats{
		Pending:         3,
		InProgress:      2,
		CompletedToday:  10,
		FailedToday:     1,
		RolledBackToday: 0,
	}

	assert.Equal(t, 3, stats.Pending)
	assert.Equal(t, 2, stats.InProgress)
}

func TestAuditStats(t *testing.T) {
	stats := AuditStats{
		EventsToday:       5000,
		SecurityEvents:    100,
		FailedAuth:        25,
		AccessDenials:     50,
		ConfigChanges:     200,
		AttestationEvents: 50,
	}

	assert.Equal(t, 5000, stats.EventsToday)
	assert.Equal(t, 100, stats.SecurityEvents)
}
