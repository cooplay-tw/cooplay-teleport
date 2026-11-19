// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gravitational/teleport/lib/observability/metrics"
)

var (
	keycloakLastSync = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "teleport_keycloak_last_successful_sync_timestamp_seconds",
		Help: "Last completed authoritative reconciliation of active Keycloak logins.",
	}, []string{"connector"})
	keycloakStaleLimit = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "teleport_keycloak_max_stale_seconds",
		Help: "Configured maximum age of authoritative reconciliation before access fails closed.",
	}, []string{"connector"})
	keycloakSyncFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "teleport_keycloak_sync_failures_total",
		Help: "Failed bounded Keycloak reconciliation passes, including journal and backend failures.",
	})
	keycloakSyncStepFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "teleport_keycloak_sync_step_failures_total",
		Help: "Failed Keycloak reconciliation steps, including failed request attempts before a retry.",
	}, []string{"connector", "step", "kind"})
	keycloakSyncPassDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "teleport_keycloak_sync_pass_seconds",
		Help:    "Duration of Keycloak reconciliation passes including fail-closed repair.",
		Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 15, 30, 120},
	})
	keycloakHealthLockActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "teleport_keycloak_health_lock_active",
		Help: "Whether the connector's Keycloak health lock exists.",
	}, []string{"connector"})
	keycloakHealthLockEvents = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "teleport_keycloak_health_lock_events_total",
		Help: "Backend-persisted count of Keycloak health locks created due to synchronization unavailability.",
	}, []string{"connector"})
)

func registerKeycloakMetrics(cfg KeycloakLifecycleConfig) error {
	if err := metrics.RegisterPrometheusCollectors(
		keycloakLastSync, keycloakStaleLimit, keycloakSyncFailures, keycloakSyncStepFailures,
		keycloakSyncPassDuration, keycloakHealthLockActive, keycloakHealthLockEvents,
	); err != nil {
		return err
	}
	for name := range cfg.Connectors {
		keycloakLastSync.WithLabelValues(name).Set(0)
		keycloakStaleLimit.WithLabelValues(name).Set(float64(cfg.MaxStaleSeconds))
	}
	return nil
}
