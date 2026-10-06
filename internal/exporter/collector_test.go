package exporter

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hushsecurity/hush-exporter/internal/hush"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) hush.Time { return hush.Time{Time: now.Add(d)} }

func ptr[T any](v T) *T { return &v }

func collector(s snapshot, tagLabels map[string]string) *Collector {
	p := &Poller{snap: s}
	c := NewCollector(p, tagLabels)
	c.now = func() time.Time { return now }
	return c
}

func TestExpiry(t *testing.T) {
	c := collector(snapshot{
		certificates: []hush.Certificate{{
			Fingerprint: "fp1", SubjectCN: "api.example.com", IssuerName: "R3",
			ExpiresAt: ptr(at(48 * time.Hour)), DeploymentIDs: []string{"dep_1"},
			Severity: ptr("high"), Tags: []hush.Tag{{Name: "prod"}, {Name: "team:payments"}},
		}},
		identityKeys: []hush.ExpiringIdentityKey{{
			IdentityKey: hush.IdentityKey{KeyID: "k1", Name: "ci secret", ExpiresAt: at(-time.Hour)},
			Identity:    hush.Issue{Fingerprint: "id1", NHIName: "ci-app", NHIType: "Azure App", Severity: "medium"},
		}},
		deployments: map[string]string{"dep_1": "prod-eu"},
		polls:       map[string]pollState{},
	}, map[string]string{"team": "team:"})

	want := `
# HELP hush_certificate_expires_in_seconds Time until a certificate with an open Hush expiry issue expires; negative once expired.
# TYPE hush_certificate_expires_in_seconds gauge
hush_certificate_expires_in_seconds{deployment="prod-eu",fingerprint="fp1",issuer="R3",severity="high",subject_cn="api.example.com",team="payments"} 172800
# HELP hush_identity_key_expires_in_seconds Time until an identity key with an open Hush expiry issue expires; negative once expired.
# TYPE hush_identity_key_expires_in_seconds gauge
hush_identity_key_expires_in_seconds{identity="ci-app",identity_fingerprint="id1",identity_type="Azure App",key="ci secret",key_id="k1",severity="medium",team=""} -3600
`
	err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"hush_certificate_expires_in_seconds", "hush_identity_key_expires_in_seconds")
	if err != nil {
		t.Error(err)
	}
}

func TestAccessManagement(t *testing.T) {
	c := collector(snapshot{
		accessManagement: accessManagement{
			Credentials: []hush.AccessCredential{
				{ID: "acr_pg", Name: "pg", Type: "postgres", Kind: "dynamic", Status: ptr("ok"), CreatedAt: at(-30 * 24 * time.Hour)},
				{ID: "acr_mq", Name: "mq", Type: "rabbitmq", Kind: "dynamic", Status: ptr("error"),
					AutoRotateRoot: true, CreatedAt: at(-40 * 24 * time.Hour), RotatedAt: ptr(at(-24 * time.Hour))},
				{ID: "acr_kv", Name: "kv", Type: "kv", Kind: "static", CreatedAt: at(-time.Hour)},
			},
			Policies: []hush.AccessPolicy{
				{ID: "apl_pg", Name: "pg", AccessCredentialID: "acr_pg", CredentialType: "postgres",
					Status: ptr("ok"), CreatedAt: at(-10 * 24 * time.Hour), RotatedAt: ptr(at(-2 * time.Hour))},
				{ID: "apl_new", Name: "new", AccessCredentialID: "acr_pg", CredentialType: "postgres",
					Status: ptr("syncing"), CreatedAt: at(-time.Minute)},
				{ID: "apl_kv", Name: "kv", AccessCredentialID: "acr_kv", CredentialType: "kv", Status: ptr("ok"), CreatedAt: at(-time.Hour)},
			},
		},
		polls: map[string]pollState{},
	}, nil)

	want := `
# HELP hush_access_policy_seconds_since_rotation Time since the access policy's dynamic credential last rotated, or since the policy was created if it never did.
# TYPE hush_access_policy_seconds_since_rotation gauge
hush_access_policy_seconds_since_rotation{credential_type="postgres",policy="new",policy_id="apl_new"} 60
hush_access_policy_seconds_since_rotation{credential_type="postgres",policy="pg",policy_id="apl_pg"} 7200
# HELP hush_access_credential_seconds_since_rotation Time since an auto-rotated access credential's root last rotated, or since it was created if it never did.
# TYPE hush_access_credential_seconds_since_rotation gauge
hush_access_credential_seconds_since_rotation{credential="mq",credential_id="acr_mq",credential_type="rabbitmq"} 86400
`
	err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"hush_access_policy_seconds_since_rotation", "hush_access_credential_seconds_since_rotation")
	if err != nil {
		t.Error(err)
	}

	// One series per status, set on the current one only.
	if n := testutil.CollectAndCount(c, "hush_access_policy_status"); n != 3*len(policyStatuses) {
		t.Errorf("policy status series = %d", n)
	}
}

func TestExporterHealth(t *testing.T) {
	c := collector(snapshot{polls: map[string]pollState{
		sourceCertificates: {up: true, lastSuccess: now.Add(-5 * time.Minute)},
		sourceIdentityKeys: {up: false, lastSuccess: now.Add(-time.Hour)},
	}}, nil)

	want := `
# HELP hush_exporter_up 1 if the last poll of the source succeeded.
# TYPE hush_exporter_up gauge
hush_exporter_up{source="access_management"} 0
hush_exporter_up{source="certificates"} 1
hush_exporter_up{source="identity_keys"} 0
# HELP hush_exporter_seconds_since_success Age of the data read from the source.
# TYPE hush_exporter_seconds_since_success gauge
hush_exporter_seconds_since_success{source="certificates"} 300
hush_exporter_seconds_since_success{source="identity_keys"} 3600
`
	err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"hush_exporter_up", "hush_exporter_seconds_since_success")
	if err != nil {
		t.Error(err)
	}
}

func TestDuplicateLabelsDoNotFailTheScrape(t *testing.T) {
	cert := hush.Certificate{Fingerprint: "fp", ExpiresAt: ptr(at(time.Hour)), DeploymentIDs: []string{"d1", "d2"}}
	c := collector(snapshot{
		certificates: []hush.Certificate{cert},
		deployments:  map[string]string{"d1": "same", "d2": "same"},
		polls:        map[string]pollState{},
	}, nil)
	if err := testutil.CollectAndCompare(c, strings.NewReader(""), "none"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "hush_certificate_expires_in_seconds"); n != 1 {
		t.Errorf("series = %d, want 1", n)
	}
}
