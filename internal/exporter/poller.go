// Package exporter polls Hush and serves what it read as metrics.
package exporter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/hushsecurity/hush-exporter/internal/hush"
)

// A source is what one poll reads; each fails or succeeds on its own.
const (
	sourceCertificates     = "certificates"
	sourceIdentityKeys     = "identity_keys"
	sourceAccessManagement = "access_management"
)

var sources = []string{sourceCertificates, sourceIdentityKeys, sourceAccessManagement}

// API is the part of the Hush API the exporter reads.
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

// snapshot is the last successful read of every source. A failed poll keeps
// the previous data, and its age shows how stale it is.
type snapshot struct {
	certificates     []hush.Certificate
	identityKeys     []hush.ExpiringIdentityKey
	accessManagement accessManagement
	deployments      map[string]string // id to name
	polls            map[string]pollState
}

// Poller reads the Hush API on a timer and keeps the last result.
type Poller struct {
	api      API
	interval time.Duration
	timeout  time.Duration

	mu   sync.RWMutex
	snap snapshot
}

func NewPoller(api API, interval time.Duration) *Poller {
	return &Poller{
		api:      api,
		interval: interval,
		timeout:  interval,
		snap:     snapshot{deployments: map[string]string{}, polls: map[string]pollState{}},
	}
}

// Run polls now and then every interval, until ctx is done.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		p.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Poll reads every source once.
func (p *Poller) Poll(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Names are a nicety: without them, labels carry the ids.
	if deployments, err := p.api.Deployments(ctx); err != nil {
		slog.Warn("poll deployments", "err", err)
	} else {
		names := make(map[string]string, len(deployments))
		for _, d := range deployments {
			names[d.ID] = d.Name
		}
		p.update(func(s *snapshot) { s.deployments = names })
	}

	poll(p, ctx, sourceCertificates, p.api.ExpiringCertificates,
		func(s *snapshot, v []hush.Certificate) { s.certificates = v })
	poll(p, ctx, sourceIdentityKeys, p.api.ExpiringIdentityKeys,
		func(s *snapshot, v []hush.ExpiringIdentityKey) { s.identityKeys = v })
	poll(p, ctx, sourceAccessManagement, p.readAccessManagement,
		func(s *snapshot, v accessManagement) { s.accessManagement = v })
}

func poll[T any](p *Poller, ctx context.Context, source string, read func(context.Context) (T, error), store func(*snapshot, T)) {
	start := time.Now()
	v, err := read(ctx)
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
	// update writes polls in place; the rest is only ever replaced.
	s.polls = make(map[string]pollState, len(p.snap.polls))
	for k, v := range p.snap.polls {
		s.polls[k] = v
	}
	return s
}
