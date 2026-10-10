// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/cooplay/secrets"
	"github.com/gravitational/teleport/lib/utils"
)

const keycloakLoginPrefix = "keycloak-login-"
const keycloakGuardPrefix = "keycloak-guard-"

// KeycloakLifecycleConfig is Auth-local configuration. It never travels through
// user APIs. All configured connectors require authoritative Admin API checks.
type KeycloakLifecycleConfig struct {
	RevocationJournalDir string                                `json:"revocation_journal_dir"`
	CAFile               string                                `json:"ca_file,omitempty"`
	PollSeconds          int                                   `json:"poll_seconds"`
	MaxSessionSeconds    int                                   `json:"max_session_seconds,omitempty"`
	MaxStaleSeconds      int                                   `json:"max_stale_seconds"`
	Connectors           map[string]KeycloakLifecycleConnector `json:"connectors"`
}

type KeycloakLifecycleConnector struct {
	Issuer            string            `json:"issuer"`
	ClientID          string            `json:"client_id"`
	AdminURL          string            `json:"admin_url"`
	ClientSecret      secrets.Reference `json:"client_secret"`
	AdminClientID     string            `json:"admin_client_id"`
	AdminClientSecret secrets.Reference `json:"admin_client_secret"`
}

type keycloakLogin struct {
	Marker    string    `json:"marker"`
	Connector string    `json:"connector"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Username  string    `json:"username"`
	SID       string    `json:"sid"`
	Groups    []string  `json:"groups"`
	Issued    time.Time `json:"issued"`
	Expires   time.Time `json:"expires"`
}

type keycloakRevocation struct {
	Expires time.Time        `json:"expires,omitempty"`
	Target  types.LockTarget `json:"target"`
	Reason  string           `json:"reason"`
	Time    time.Time        `json:"time"`
}

func keycloakDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func keycloakLifecycleKey(parts ...string) backend.Key {
	return backend.NewKey(append([]string{"cooplay", "keycloak", "lifecycle"}, parts...)...)
}
func keycloakGuard(connector string) string { return keycloakGuardPrefix + keycloakDigest(connector) }

// NewManagedKeycloakService constructs the deployment service. The small
// NewKeycloakService constructor remains useful for protocol unit tests only;
// the process startup always uses this constructor when SSO is enabled.
func NewManagedKeycloakService(a *Server, cfg KeycloakLifecycleConfig) (OIDCService, error) {
	if cfg.MaxSessionSeconds != 0 && (cfg.MaxSessionSeconds < int(keycloakSessionTTL/time.Second) || cfg.MaxSessionSeconds > int(keycloakMaxSessionTTL/time.Second)) {
		return nil, trace.BadParameter("Keycloak max_session_seconds must be omitted or between 300 and 86400")
	}
	if cfg.PollSeconds < 1 || cfg.PollSeconds > 30 || cfg.MaxStaleSeconds < cfg.PollSeconds*2 || cfg.MaxStaleSeconds > 120 || len(cfg.Connectors) == 0 {
		return nil, trace.BadParameter("Keycloak requires a 1..30s poll interval, 2 intervals..120s staleness, and connectors")
	}
	for name, c := range cfg.Connectors {
		u, err := keycloakHTTPSURL(c.Issuer)
		if err != nil || !strings.Contains(u.Path, "/realms/") || strings.HasSuffix(u.Path, "/") || c.AdminClientID == "" || c.ClientID == "" || !keycloakRoleName.MatchString(name) {
			return nil, trace.BadParameter("invalid Keycloak lifecycle connector")
		}
		admin, adminErr := keycloakHTTPSURL(c.AdminURL)
		pos := strings.LastIndex(u.Path, "/realms/")
		realm := u.Path[pos+len("/realms/"):]
		// Only this trusted Auth-local origin may receive the Admin bearer.
		// No discovery/claim/user input can change it or the fixed realm path.
		if adminErr != nil || u.RawPath != "" || admin.RawPath != "" || path.Clean(u.Path) != u.Path || path.Clean(admin.Path) != admin.Path || !keycloakRoleName.MatchString(realm) ||
			admin.Path != u.Path[:pos]+"/admin/realms/"+realm {
			return nil, trace.BadParameter("explicit HTTPS Admin URL for the issuer realm required")
		}
		if c.ClientSecret.Validate() != nil || c.AdminClientSecret.Validate() != nil || c.ClientSecret.Multiline || c.AdminClientSecret.Multiline {
			return nil, trace.BadParameter("invalid Keycloak secret reference")
		}
	}
	if !filepath.IsAbs(cfg.RevocationJournalDir) {
		return nil, trace.BadParameter("absolute Keycloak revocation journal directory required")
	}
	if err := os.MkdirAll(cfg.RevocationJournalDir, 0700); err != nil {
		return nil, trace.BadParameter("Keycloak revocation journal unavailable")
	}
	info, err := os.Lstat(cfg.RevocationJournalDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, trace.BadParameter("Keycloak revocation journal must be a private directory")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, trace.BadParameter("Keycloak CA file unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, trace.BadParameter("system CA pool unavailable")
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, trace.BadParameter("invalid Keycloak CA file")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	if err := registerKeycloakMetrics(cfg); err != nil {
		return nil, trace.Wrap(err)
	}
	svc := &keycloakService{a: a, lifecycle: &cfg, httpClient: &http.Client{Transport: transport}}
	if err := svc.replayJournal(a.CloseContext()); err != nil {
		return nil, err
	}
	// Synchronously fence every connector before Auth can expose listeners.
	// Never inherit a successful health timestamp from a previous process/backup.
	for name := range cfg.Connectors {
		if err := svc.ensureLock(a.CloseContext(), "keycloak-health-"+keycloakDigest(name), types.LockTarget{Role: keycloakGuard(name)}, "startup-reconciliation-required"); err != nil {
			return nil, err
		}
		if err := a.bk.Delete(a.CloseContext(), keycloakLifecycleKey("health", name)); err != nil && !trace.IsNotFound(err) {
			return nil, err
		}
		keycloakLastSync.WithLabelValues(name).Set(0)
	}
	return svc, nil
}

func loadKeycloakLifecycle(a *Server) (*keycloakService, error) {
	path := os.Getenv("TELEPORT_KEYCLOAK_CONFIG")
	if path == "" {
		return nil, trace.BadParameter("TELEPORT_KEYCLOAK_CONFIG is required when Keycloak SSO is enabled")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return nil, trace.BadParameter("Keycloak lifecycle configuration unavailable")
	}
	var cfg KeycloakLifecycleConfig
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF {
		return nil, trace.BadParameter("invalid Keycloak lifecycle configuration")
	}
	svc, err := NewManagedKeycloakService(a, cfg)
	if err != nil {
		return nil, err
	}
	return svc.(*keycloakService), nil
}

func (s *keycloakService) httpContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
	}
	return keycloakHTTPContext(ctx)
}

func (s *keycloakService) lifecycleConnector(ctx context.Context, c types.OIDCConnector) error {
	if s.lifecycle == nil {
		return nil
	}
	cfg, ok := s.lifecycle.Connectors[c.GetName()]
	if !ok || cfg.Issuer != c.GetIssuerURL() || cfg.ClientID != c.GetClientID() {
		return trace.AccessDenied("Keycloak lifecycle connector not configured")
	}
	secret, err := (secrets.Reader{}).Read(ctx, cfg.ClientSecret)
	if err != nil {
		return trace.AccessDenied("Keycloak client secret unavailable")
	}
	c.SetClientSecret(secret)
	return nil
}

func (s *keycloakService) lifecyclePut(ctx context.Context, key backend.Key, value any, expires time.Time, create bool) error {
	data, err := json.Marshal(value)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{Key: key, Value: data, Expires: expires}
	if create {
		_, err = s.a.bk.Create(ctx, item)
	} else {
		_, err = s.a.bk.Put(ctx, item)
	}
	return trace.Wrap(err)
}

func (s *keycloakService) revoked(ctx context.Context, kind, id string) error {
	_, err := s.a.bk.Get(ctx, keycloakLifecycleKey("revocations", kind, id))
	if trace.IsNotFound(err) {
		return nil
	}
	return trace.AccessDenied("Keycloak identity is revoked or revocation state is unavailable")
}

func (s *keycloakService) markerRole(ctx context.Context, name string, expires time.Time) error {
	role := &types.RoleV6{Kind: types.KindRole, Version: types.V8, Metadata: types.Metadata{Name: name, Labels: map[string]string{keycloakUserLabel: "marker"}}, Spec: types.RoleSpecV6{Options: types.RoleOptions{MaxSessionTTL: types.Duration(s.sessionTTL()), DisconnectExpiredCert: true, Lock: constants.LockingModeStrict}}}
	if !expires.IsZero() {
		role.SetExpiry(expires.Add(time.Hour))
	}
	// CheckAndSetDefaults is intentionally applied, then every allow field is
	// cleared: the marker adds no resource grants. Native implicit rules remain.
	if err := role.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	role.Spec.Allow = types.RoleConditions{}
	role.Spec.Options.SSHFileCopy = types.NewBoolOption(false)
	role.Spec.Options.SSHPortForwarding = &types.SSHPortForwarding{Local: &types.SSHLocalPortForwarding{Enabled: types.NewBoolOption(false)}, Remote: &types.SSHRemotePortForwarding{Enabled: types.NewBoolOption(false)}}
	role.Spec.Options.PortForwarding = nil
	role.Spec.Options.DesktopClipboard = types.NewBoolOption(false)
	role.Spec.Options.RecordSession = &types.RecordSession{SSH: constants.SessionRecordingModeStrict}
	if err := role.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	existing, err := s.a.Services.GetRole(ctx, name)
	if err == nil {
		concrete, ok := existing.(*types.RoleV6)
		if !ok || concrete.Metadata.Labels[keycloakUserLabel] != "marker" {
			return trace.AccessDenied("Keycloak marker role collision")
		}
		// A reviewed Auth-local TTL change may update only this zero-grant
		// marker's cap. All other options/grants must still match exactly.
		previousTTL := concrete.Spec.Options.MaxSessionTTL
		concrete.Spec.Options.MaxSessionTTL = role.Spec.Options.MaxSessionTTL
		if !keycloakRoleSpecEqual(concrete.Spec, role.Spec) {
			return trace.AccessDenied("Keycloak marker role collision")
		}
		if previousTTL != role.Spec.Options.MaxSessionTTL {
			_, err = s.a.Services.UpsertRole(ctx, concrete)
			return trace.Wrap(err)
		}
		return nil
	}
	if !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	_, err = s.a.UpsertRole(ctx, role)
	return trace.Wrap(err)
}

func (s *keycloakService) prepareLogin(ctx context.Context, c types.OIDCConnector, subject, sid, username string, groups []string, expires time.Time) (*keycloakLogin, error) {
	if s.lifecycle == nil {
		return nil, nil
	}
	if err := s.checkHealth(ctx, c.GetName()); err != nil {
		return nil, err
	}
	if sid == "" || len(sid) > 512 {
		return nil, trace.AccessDenied("Keycloak session ID required")
	}
	if err := s.revoked(ctx, "users", username); err != nil {
		return nil, err
	}
	if err := s.revoked(ctx, "sid", keycloakDigest(c.GetIssuerURL()+"\x00"+sid)); err != nil {
		return nil, err
	}
	// Login cannot race past an outage using only an earlier ID token.
	account, err := s.adminUser(ctx, c.GetName(), subject)
	if err != nil {
		return nil, trace.AccessDenied("Keycloak account verification unavailable")
	}
	if !account.enabled {
		return nil, s.revokeAccount(ctx, username, "account-disabled")
	}
	if !slices.Contains(account.sessions, sid) {
		return nil, trace.AccessDenied("Keycloak client session ended")
	}
	var mapped []string
	for _, mapping := range c.GetClaimsToRoles() {
		if slices.Contains(groups, mapping.Value) {
			if !slices.Contains(account.groups, mapping.Value) {
				return nil, trace.AccessDenied("Keycloak group membership changed during login")
			}
			if !slices.Contains(mapped, mapping.Value) {
				mapped = append(mapped, mapping.Value)
			}
		}
	}
	random, err := utils.CryptoRandomHex(32)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	login := &keycloakLogin{Marker: keycloakLoginPrefix + random, Connector: c.GetName(), Issuer: c.GetIssuerURL(), Subject: subject, Username: username, SID: sid, Groups: mapped, Issued: s.a.clock.Now(), Expires: expires}
	if err = s.markerRole(ctx, login.Marker, expires); err != nil {
		return nil, err
	}
	if err = s.markerRole(ctx, keycloakGuard(c.GetName()), time.Time{}); err != nil {
		return nil, err
	}
	if err = s.lifecyclePut(ctx, keycloakLifecycleKey("logins", login.Marker), login, expires.Add(24*time.Hour), true); err != nil {
		return nil, err
	}
	if err = s.checkLogin(ctx, login); err != nil {
		return nil, err
	}
	return login, nil
}

func (s *keycloakService) checkLogin(ctx context.Context, login *keycloakLogin) error {
	if login == nil {
		return nil
	}
	if err := s.checkHealth(ctx, login.Connector); err != nil {
		return err
	}
	return s.checkLoginRevocations(ctx, login)
}

func (s *keycloakService) checkLoginRevocations(ctx context.Context, login *keycloakLogin) error {
	if login == nil {
		return nil
	}
	for _, key := range [][2]string{{"users", login.Username}, {"roles", login.Marker}, {"sid", keycloakDigest(login.Issuer + "\x00" + login.SID)}} {
		if err := s.revoked(ctx, key[0], key[1]); err != nil {
			return err
		}
	}
	// Sub-only logout applies to existing logins, not future authentication.
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("subject-logout", keycloakDigest(login.Issuer+"\x00"+login.Subject)))
	if err == nil {
		var cutoff time.Time
		if json.Unmarshal(item.Value, &cutoff) != nil || !login.Issued.After(cutoff) {
			return trace.AccessDenied("Keycloak login has been logged out")
		}
	} else if !trace.IsNotFound(err) {
		return trace.AccessDenied("Keycloak logout state unavailable")
	}
	return nil
}

func (s *keycloakService) revokeAccount(ctx context.Context, user, reason string) error {
	if err := s.persistRevocation(ctx, "users", user, types.LockTarget{User: user}, reason, time.Time{}); err != nil {
		return err
	}
	return trace.AccessDenied("Keycloak account revoked")
}

func (s *keycloakService) persistRevocation(ctx context.Context, kind, id string, target types.LockTarget, reason string, expires time.Time) error {
	record := keycloakRevocation{Target: target, Reason: reason, Time: s.a.clock.Now().UTC(), Expires: expires}
	if err := s.appendJournal(keycloakJournalEntry{Kind: kind, ID: id, Revocation: record, Expires: expires}); err != nil {
		_ = s.lifecyclePut(ctx, keycloakLifecycleKey("revocations", kind, id), record, expires, true)
		_ = s.ensureLock(ctx, "keycloak-revoke-"+keycloakDigest(kind+"\x00"+id), target, reason, expires)
		return err
	}
	// Durable intent precedes native lock application. Reconciliation repairs a
	// crash between these operations; logins check the durable intent directly.
	if err := s.lifecyclePut(ctx, keycloakLifecycleKey("revocations", kind, id), record, expires, true); err != nil && !trace.IsAlreadyExists(err) {
		return err
	}
	return s.ensureLock(ctx, "keycloak-revoke-"+keycloakDigest(kind+"\x00"+id), target, reason, expires)
}

func (s *keycloakService) ensureLock(ctx context.Context, name string, target types.LockTarget, reason string, expirations ...time.Time) error {
	var expires time.Time
	if len(expirations) > 0 {
		expires = expirations[0]
	}
	existing, err := s.a.Services.GetLock(ctx, name)
	if err == nil && existing.Target() == target && ((expires.IsZero() && existing.LockExpiry() == nil) || (existing.LockExpiry() != nil && existing.LockExpiry().Equal(expires))) {
		return nil
	}
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	lock, err := types.NewLock(name, types.LockSpecV2{Target: target, Message: "Keycloak: " + reason})
	if err != nil {
		return trace.Wrap(err)
	}
	if !expires.IsZero() {
		lock.SetLockExpiry(&expires)
		lock.SetExpiry(expires)
	}
	// Server.UpsertLock emits the native lock.created event. The durable record
	// additionally retains the reason and time even if the event sink is down.
	return s.a.UpsertLock(ctx, lock)
}

func (s *keycloakService) logins(ctx context.Context, visit func(keycloakLogin) error) error {
	prefix := keycloakLifecycleKey("logins")
	for item, err := range s.a.bk.Items(ctx, backend.ItemsParams{StartKey: prefix, EndKey: backend.RangeEnd(prefix)}) {
		if err != nil {
			return trace.Wrap(err)
		}
		var login keycloakLogin
		if json.Unmarshal(item.Value, &login) != nil {
			return trace.BadParameter("corrupt Keycloak login record")
		}
		if err := visit(login); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileKeycloak performs one bounded pass and is also used by the local
// integration tests. It never enumerates unrelated Teleport users or IdP data.
func ReconcileKeycloak(ctx context.Context, svc OIDCService) error {
	s, ok := svc.(*keycloakService)
	if !ok || s.lifecycle == nil {
		return trace.BadParameter("managed Keycloak service required")
	}
	return s.reconcile(ctx)
}

func (s *keycloakService) reconcile(ctx context.Context) (resultErr error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	defer func() {
		if resultErr == nil {
			return
		}
		keycloakSyncFailures.Inc()
		repair, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for name := range s.lifecycle.Connectors {
			if s.checkHealth(repair, name) != nil {
				if err := s.ensureLock(repair, "keycloak-health-"+keycloakDigest(name), types.LockTarget{Role: keycloakGuard(name)}, "synchronization-unavailable"); err != nil {
					s.a.logger.ErrorContext(repair, "Keycloak fail-closed lock could not be persisted")
				}
			}
		}
	}()
	var first error
	if err := s.replayJournal(ctx); err != nil {
		return err
	}
	// Replay all durable revocations, including accounts whose short-lived user
	// resources have expired. Records are never implicitly undone by re-enable.
	prefix := keycloakLifecycleKey("revocations")
	for item, err := range s.a.bk.Items(ctx, backend.ItemsParams{StartKey: prefix, EndKey: backend.RangeEnd(prefix)}) {
		if err != nil {
			return trace.Wrap(err)
		}
		var r keycloakRevocation
		if json.Unmarshal(item.Value, &r) != nil {
			return trace.BadParameter("corrupt Keycloak revocation record")
		}
		kind, id := "users", r.Target.User
		if r.Target.Role != "" {
			kind, id = "roles", r.Target.Role
		}
		if r.Target.User == "" && r.Target.Role == "" {
			continue
		}
		if err := s.ensureLock(ctx, "keycloak-revoke-"+keycloakDigest(kind+"\x00"+id), r.Target, r.Reason, r.Expires); err != nil {
			return err
		}
	}
	for name := range s.lifecycle.Connectors {
		checked := map[string]keycloakAccountState{}
		// Probe private Admin reachability/authorization even with zero logins.
		get, cancel, err := s.adminReader(ctx, name)
		if err == nil {
			var count *int
			status, probeErr := get(s.lifecycle.Connectors[name].AdminURL+"/users/count", &count)
			if probeErr != nil || status != http.StatusOK || count == nil || *count < 0 {
				err = trace.AccessDenied("Keycloak synchronization probe failed")
			}
		}
		if err == nil {
			err = s.logins(ctx, func(login keycloakLogin) error {
				if login.Connector != name || !s.a.clock.Now().Before(login.Expires) {
					return nil
				}
				if _, err := s.a.bk.Get(ctx, keycloakLifecycleKey("revocations", "users", login.Username)); err == nil {
					return nil
				} else if !trace.IsNotFound(err) {
					return trace.Wrap(err)
				}
				account, found := checked[login.Subject]
				if !found {
					var err error
					account, err = readKeycloakAccount(get, s.lifecycle.Connectors[name], login.Subject)
					if err != nil {
						return err
					}
					checked[login.Subject] = account
				}
				groups, enabled := account.groups, account.enabled
				reason := ""
				if !enabled {
					reason = "account-disabled"
				}
				for _, group := range login.Groups {
					if !slices.Contains(groups, group) {
						reason = "group-removed"
					}
				}
				if !enabled {
					return s.persistRevocation(ctx, "users", login.Username, types.LockTarget{User: login.Username}, "account-disabled", time.Time{})
				}
				if reason != "" {
					// Retire this credential generation without blocking a fresh
					// login using the user's remaining authoritative memberships.
					return s.persistRevocation(ctx, "roles", login.Marker, types.LockTarget{Role: login.Marker}, reason, login.Expires.Add(24*time.Hour))
				}
				if !slices.Contains(account.sessions, login.SID) {
					return s.persistRevocation(ctx, "roles", login.Marker, types.LockTarget{Role: login.Marker}, "idp-session-ended", login.Expires.Add(24*time.Hour))
				}
				if err := s.checkLoginRevocations(ctx, &login); err != nil {
					return s.persistRevocation(ctx, "roles", login.Marker, types.LockTarget{Role: login.Marker}, "logout", login.Expires.Add(24*time.Hour))
				}
				return nil
			})
		}
		cancel()
		health := keycloakLifecycleKey("health", name)
		guardLock := "keycloak-health-" + keycloakDigest(name)
		if err == nil {
			err = s.lifecyclePut(ctx, health, s.a.clock.Now(), time.Time{}, false)
			if err == nil {
				err = s.a.DeleteLock(ctx, guardLock)
				if trace.IsNotFound(err) {
					err = nil
				}
			}
			if err == nil {
				keycloakLastSync.WithLabelValues(name).Set(float64(s.a.clock.Now().Unix()))
				_ = s.a.DeleteClusterAlert(ctx, guardLock)
			}
		} else {
			item, getErr := s.a.bk.Get(ctx, health)
			var last time.Time
			if getErr == nil {
				_ = json.Unmarshal(item.Value, &last)
			}
			if last.IsZero() || s.a.clock.Now().Sub(last) > time.Duration(s.lifecycle.MaxStaleSeconds)*time.Second {
				_ = s.ensureLock(ctx, guardLock, types.LockTarget{Role: keycloakGuard(name)}, "synchronization-unavailable")
			}
			alert, alertErr := types.NewClusterAlert(guardLock, "Keycloak synchronization failed; inspect Auth logs and identity connectivity. Access fails closed after the configured staleness limit.", types.WithAlertSeverity(types.AlertSeverity_HIGH), types.WithAlertLabel(types.AlertOnLogin, "yes"))
			if alertErr == nil {
				_ = s.a.UpsertClusterAlert(ctx, alert)
			}
		}
		if err != nil && first == nil {
			first = trace.ConnectionProblem(nil, "Keycloak reconciliation failed")
		}
	}
	return first
}

func (s *keycloakService) runLifecycle(ctx context.Context) {
	delay := time.NewTimer(0)
	defer delay.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-delay.C:
		}
		pass, cancel := context.WithTimeout(ctx, time.Duration(s.lifecycle.MaxStaleSeconds)*time.Second)
		if err := s.reconcile(pass); err != nil && ctx.Err() == nil {
			s.a.logger.ErrorContext(ctx, "Keycloak reconciliation failed; persistent revocations retained")
		}
		cancel()
		// Retry on the next bounded pass, with jitter to avoid synchronized
		// Admin API bursts when several Auth instances restart together.
		interval := time.Duration(s.lifecycle.PollSeconds) * time.Second
		delay.Reset(interval + time.Duration(rand.Int64N(int64(interval/5)+1)))
	}
}

// adminReader obtains a short-lived service token using the public issuer, but
// sends it only to the explicitly configured private Admin origin. No redirects.
type keycloakAdminRead func(string, any) (int, error)
type keycloakAccountState struct {
	groups   []string
	sessions []string
	enabled  bool
}

func (s *keycloakService) adminReader(ctx context.Context, connector string) (keycloakAdminRead, context.CancelFunc, error) {
	ctx, cancel := s.httpContext(ctx)
	fail := func() (keycloakAdminRead, context.CancelFunc, error) {
		return nil, cancel, trace.AccessDenied("Keycloak synchronization authentication unavailable")
	}
	cfg, ok := s.lifecycle.Connectors[connector]
	if !ok {
		return fail()
	}
	secret, err := (secrets.Reader{}).Read(ctx, cfg.AdminClientSecret)
	if err != nil {
		return fail()
	}
	client := ctx.Value(oauth2.HTTPClient).(*http.Client)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Issuer+"/protocol/openid-connect/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	if err != nil {
		return fail()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.AdminClientID, secret)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	status, err := keycloakAdminJSON(client, req, &token)
	if err != nil || status != http.StatusOK || token.AccessToken == "" {
		return fail()
	}
	get := func(endpoint string, out any) (int, error) {
		// Internal callers use fixed suffixes; keep the credential boundary explicit.
		if !strings.HasPrefix(endpoint, cfg.AdminURL+"/users/") {
			return 0, trace.AccessDenied("invalid Keycloak Admin path")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return 0, trace.AccessDenied("invalid Keycloak Admin request")
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		return keycloakAdminJSON(client, req, out)
	}
	return get, cancel, nil
}

func (s *keycloakService) adminUser(ctx context.Context, connector, subject string) (keycloakAccountState, error) {
	get, cancel, err := s.adminReader(ctx, connector)
	defer cancel()
	if err != nil {
		return keycloakAccountState{}, err
	}
	return readKeycloakAccount(get, s.lifecycle.Connectors[connector], subject)
}

// Only view-users operations; no writes or realm-admin. Keycloak 26.8 sessions
// are unpaginated. A bounded/malformed response fails closed, never implies logout.
func readKeycloakAccount(get keycloakAdminRead, cfg KeycloakLifecycleConnector, subject string) (keycloakAccountState, error) {
	var result keycloakAccountState
	if subject == "" || len(subject) > 512 || strings.ContainsAny(subject, "/\\?#%") || subject == "." || subject == ".." {
		return result, trace.AccessDenied("invalid Keycloak subject")
	}
	base := cfg.AdminURL + "/users/" + url.PathEscape(subject)
	var user struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	status, err := get(base, &user)
	if err == nil && status == 404 {
		return result, nil
	}
	if err != nil || status != 200 || user.ID != subject {
		return result, trace.AccessDenied("Keycloak account query failed")
	}
	if !user.Enabled {
		return result, nil
	}
	result.enabled = true
	var sessions []struct {
		ID      string            `json:"id"`
		UserID  string            `json:"userId"`
		Clients map[string]string `json:"clients"`
	}
	status, err = get(base+"/sessions", &sessions)
	if err != nil || status != 200 || sessions == nil {
		return result, trace.AccessDenied("Keycloak session query failed")
	}
	for _, session := range sessions {
		if session.ID == "" || session.UserID != subject || session.Clients == nil {
			return result, trace.AccessDenied("invalid Keycloak session")
		}
		for _, client := range session.Clients {
			if client == cfg.ClientID {
				result.sessions = append(result.sessions, session.ID)
				break
			}
		}
	}
	for first := 0; first < 10000; first += 100 {
		var page []struct {
			Path string `json:"path"`
		}
		status, err = get(base+"/groups?briefRepresentation=true&first="+strconv.Itoa(first)+"&max=100", &page)
		if err != nil || status != 200 || page == nil {
			return result, trace.AccessDenied("Keycloak group query failed")
		}
		for _, g := range page {
			if g.Path == "" {
				return result, trace.AccessDenied("Keycloak group path unavailable")
			}
			result.groups = append(result.groups, g.Path)
		}
		if len(page) < 100 {
			return result, nil
		}
	}
	return result, trace.AccessDenied("Keycloak group query limit exceeded")
}

func keycloakAdminJSON(client *http.Client, req *http.Request, out any) (int, error) {
	response, err := client.Do(req)
	if err != nil {
		return 0, trace.ConnectionProblem(nil, "Keycloak request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		return response.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 || json.Unmarshal(data, out) != nil {
		return response.StatusCode, trace.BadParameter("invalid Keycloak response")
	}
	return response.StatusCode, nil
}

func keycloakRoleSpecEqual(a, b types.RoleSpecV6) bool {
	left, err := a.Marshal()
	if err != nil {
		return false
	}
	right, err := b.Marshal()
	return err == nil && bytes.Equal(left, right)
}

func (s *keycloakService) checkHealth(ctx context.Context, connector string) error {
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("health", connector))
	if err != nil {
		return trace.AccessDenied("Keycloak reconciliation has not completed")
	}
	var last time.Time
	if json.Unmarshal(item.Value, &last) != nil || last.IsZero() || s.a.clock.Now().Sub(last) > time.Duration(s.lifecycle.MaxStaleSeconds)*time.Second {
		return trace.AccessDenied("Keycloak reconciliation is stale")
	}
	return nil
}
