// Package exporter polls Hush and serves what it read as metrics.
package exporter

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hushsecurity/hush-exporter/internal/hush"
)

const (
	sourceCertificates     = "certificates"
	sourceIdentityKeys     = "identity_keys"
	sourceAccessManagement = "access_management"
)

var sources = []string{sourceCertificates, sourceIdentityKeys, sourceAccessManagement}

type API interface {
	ExpiringCertificates(context.Context) ([]hush.Certificate, error)
	ExpiringIdentityKeys(context.Context) ([]hush.ExpiringIdentityKey, error)
	AccessPolicies(context.Context) ([]hush.AccessPolicy, error)
	AccessCredentials(context.Context) ([]hush.AccessCredential, error)
	SecretStores(context.Context) ([]hush.SecretStore, error)
	SecretStoreStatuses(context.Context, string) ([]hush.SecretStoreStatus, error)
	Deployments(context.Context) ([]hush.Deployment, error)
}

type secretStore struct {
	hush.SecretStore
	Statuses []hush.SecretStoreStatus
}

type accessManagement struct {
	Policies    []hush.AccessPolicy
	Credentials []hush.AccessCredential
	Stores      []secretStore
}

type pollState struct {
	up          bool
	lastSuccess time.Time
}

// snapshot keeps the last good read of each source.
type snapshot struct {
	certificates     []hush.Certificate
	identityKeys     []hush.ExpiringIdentityKey
	accessManagement accessManagement
	deployments      map[string]string // id to name
	polls            map[string]pollState
}

const (
	// Findings change about daily; status is what alerts on breakage.
	findingsInterval  = time.Hour
	statusInterval    = 5 * time.Minute
	pollTimeout       = 5 * time.Minute
	deploymentsMaxAge = 24 * time.Hour
)

type Poller struct {
	api     API
	enabled []string

	deploymentsAt time.Time

	mu   sync.RWMutex
	snap snapshot
}

func NewPoller(api API, enabled []string) (*Poller, error) {
	if len(enabled) == 0 {
		enabled = sources
	}
	for _, source := range enabled {
		if !slices.Contains(sources, source) {
			return nil, fmt.Errorf("unknown source %q, want one of %s", source, strings.Join(sources, ", "))
		}
	}
	return &Poller{
		api:     api,
		enabled: enabled,
		snap:    snapshot{deployments: map[string]string{}, polls: map[string]pollState{}},
	}, nil
}

// Run keeps the two loops apart, so slow findings never delay status.
func (p *Poller) Run(ctx context.Context) {
	go every(ctx, statusInterval, p.pollStatus)
	every(ctx, findingsInterval, func(ctx context.Context) {
		p.refreshDeployments(ctx)
		p.pollFindings(ctx)
	})
}

func every(ctx context.Context, interval time.Duration, poll func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Poller) pollFindings(ctx context.Context) {
	if p.on(sourceCertificates) {
		poll(p, ctx, sourceCertificates, p.api.ExpiringCertificates,
			func(s *snapshot, v []hush.Certificate) { s.certificates = v })
	}
	if p.on(sourceIdentityKeys) {
		poll(p, ctx, sourceIdentityKeys, p.api.ExpiringIdentityKeys,
			func(s *snapshot, v []hush.ExpiringIdentityKey) { s.identityKeys = v })
	}
}

func (p *Poller) pollStatus(ctx context.Context) {
	if p.on(sourceAccessManagement) {
		poll(p, ctx, sourceAccessManagement, p.readAccessManagement,
			func(s *snapshot, v accessManagement) { s.accessManagement = v })
	}
}

// Daily, or sooner for an unknown id; on failure labels carry ids.
func (p *Poller) refreshDeployments(ctx context.Context) {
	if time.Since(p.deploymentsAt) < deploymentsMaxAge && !p.unknownDeployment() {
		return
	}
	deployments, err := withTimeout(ctx, p.api.Deployments)
	if err != nil {
		slog.Warn("poll deployments", "err", err)
		return
	}
	p.deploymentsAt = time.Now()
	names := make(map[string]string, len(deployments))
	for _, d := range deployments {
		names[d.ID] = d.Name
	}
	p.update(func(s *snapshot) { s.deployments = names })
}

func (p *Poller) unknownDeployment() bool {
	s := p.snapshot()
	for _, cert := range s.certificates {
		for _, id := range cert.DeploymentIDs {
			if _, ok := s.deployments[id]; !ok {
				return true
			}
		}
	}
	for _, apl := range s.accessManagement.Policies {
		for _, id := range apl.DeploymentIDs {
			if _, ok := s.deployments[id]; !ok {
				return true
			}
		}
	}
	for _, store := range s.accessManagement.Stores {
		for _, st := range store.Statuses {
			if _, ok := s.deployments[st.DeploymentID]; !ok {
				return true
			}
		}
	}
	return false
}

func (p *Poller) on(source string) bool { return slices.Contains(p.enabled, source) }

func poll[T any](p *Poller, ctx context.Context, source string, read func(context.Context) (T, error), store func(*snapshot, T)) {
	start := time.Now()
	v, err := withTimeout(ctx, read)
	if err != nil {
		slog.Error("poll", "source", source, "err", err)
		p.update(func(s *snapshot) {
			state := s.polls[source]
			state.up = false
			s.polls[source] = state
		})
		return
	}
	slog.Info("poll", "source", source, "took", time.Since(start).Round(time.Millisecond))
	p.update(func(s *snapshot) {
		store(s, v)
		s.polls[source] = pollState{up: true, lastSuccess: time.Now()}
	})
}

func withTimeout[T any](ctx context.Context, read func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	return read(ctx)
}

func (p *Poller) readAccessManagement(ctx context.Context) (accessManagement, error) {
	var am accessManagement
	var err error
	if am.Policies, err = p.api.AccessPolicies(ctx); err != nil {
		return am, err
	}
	if am.Credentials, err = p.api.AccessCredentials(ctx); err != nil {
		return am, err
	}
	stores, err := p.api.SecretStores(ctx)
	if err != nil {
		return am, err
	}
	for _, store := range stores {
		statuses, err := p.api.SecretStoreStatuses(ctx, store.ID)
		if err != nil {
			return am, err
		}
		am.Stores = append(am.Stores, secretStore{store, statuses})
	}
	return am, nil
}

func (p *Poller) update(f func(*snapshot)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(&p.snap)
}

func (p *Poller) snapshot() snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := p.snap
	// polls is written in place.
	s.polls = make(map[string]pollState, len(p.snap.polls))
	for k, v := range p.snap.polls {
		s.polls[k] = v
	}
	return s
}
