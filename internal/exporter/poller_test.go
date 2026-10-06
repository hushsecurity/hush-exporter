package exporter

import (
	"context"
	"errors"
	"testing"

	"github.com/hushsecurity/hush-exporter/internal/hush"
)

type fakeAPI struct {
	calls           map[string]int
	certErr         error
	certDeployments []string
}

func (f *fakeAPI) call(name string) { f.calls[name]++ }

func (f *fakeAPI) ExpiringCertificates(context.Context) ([]hush.Certificate, error) {
	f.call("certificates")
	if f.certErr != nil {
		return nil, f.certErr
	}
	return []hush.Certificate{{ID: "c1", DeploymentIDs: f.certDeployments}}, nil
}

func (f *fakeAPI) ExpiringIdentityKeys(context.Context) ([]hush.ExpiringIdentityKey, error) {
	f.call("identity_keys")
	return nil, nil
}

func (f *fakeAPI) AccessPolicies(context.Context) ([]hush.AccessPolicy, error) {
	f.call("policies")
	return nil, nil
}

func (f *fakeAPI) AccessCredentials(context.Context) ([]hush.AccessCredential, error) {
	return nil, nil
}

func (f *fakeAPI) SecretStores(context.Context) ([]hush.SecretStore, error) { return nil, nil }

func (f *fakeAPI) SecretStoreStatuses(context.Context, string) ([]hush.SecretStoreStatus, error) {
	return nil, nil
}

func (f *fakeAPI) Deployments(context.Context) ([]hush.Deployment, error) {
	f.call("deployments")
	return []hush.Deployment{{ID: "dep_1", Name: "prod"}}, nil
}

func TestUnknownSource(t *testing.T) {
	if _, err := NewPoller(&fakeAPI{}, []string{"certificates", "nope"}); err == nil {
		t.Error("unknown source accepted")
	}
}

func TestOnlyEnabledSourcesArePolled(t *testing.T) {
	api := &fakeAPI{calls: map[string]int{}}
	p, err := NewPoller(api, []string{sourceCertificates})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.pollFindings(ctx)
	p.pollStatus(ctx)
	if api.calls["certificates"] != 1 || api.calls["identity_keys"] != 0 || api.calls["policies"] != 0 {
		t.Errorf("calls = %v", api.calls)
	}
}

func TestFailedPollKeepsData(t *testing.T) {
	api := &fakeAPI{calls: map[string]int{}}
	p, _ := NewPoller(api, nil)
	ctx := context.Background()
	p.pollFindings(ctx)
	api.certErr = errors.New("down")
	p.pollFindings(ctx)

	s := p.snapshot()
	if len(s.certificates) != 1 {
		t.Errorf("certificates = %+v, want the last good read", s.certificates)
	}
	if state := s.polls[sourceCertificates]; state.up || state.lastSuccess.IsZero() {
		t.Errorf("state = %+v, want down with a last success", state)
	}
}

func TestDeploymentNamesAreCached(t *testing.T) {
	api := &fakeAPI{calls: map[string]int{}, certDeployments: []string{"dep_1"}}
	p, _ := NewPoller(api, nil)
	ctx := context.Background()
	for range 3 {
		p.refreshDeployments(ctx)
		p.pollFindings(ctx)
	}
	if api.calls["deployments"] != 1 {
		t.Errorf("deployment fetches = %d, want 1", api.calls["deployments"])
	}

	// An id it does not know refetches.
	api.certDeployments = []string{"dep_new"}
	p.pollFindings(ctx)
	p.refreshDeployments(ctx)
	if api.calls["deployments"] != 2 {
		t.Errorf("deployment fetches = %d, want 2", api.calls["deployments"])
	}
}
