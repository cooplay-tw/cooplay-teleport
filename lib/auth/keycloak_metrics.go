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
)

func registerKeycloakMetrics(cfg KeycloakLifecycleConfig) error {
	if err := metrics.RegisterPrometheusCollectors(keycloakLastSync, keycloakStaleLimit, keycloakSyncFailures); err != nil {
		return err
	}
	for name := range cfg.Connectors {
		keycloakLastSync.WithLabelValues(name).Set(0)
		keycloakStaleLimit.WithLabelValues(name).Set(float64(cfg.MaxStaleSeconds))
	}
	return nil
}
