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
	p := &Poller{snap: s, enabled: sources}
	c, err := NewCollector(p, tagLabels)
	if err != nil {
		panic(err)
	}
	return c
}

func TestExpiry(t *testing.T) {
	c := collector(snapshot{
		certificates: []hush.Certificate{{
			ID: "nhi-c1", SubjectCN: "api.example.com", IssuerName: "R3",
			ExpiresAt: ptr(at(48 * time.Hour)), DeploymentIDs: []string{"dep_1"},
			Tags: []hush.Tag{{Name: "prod"}, {Name: "team:payments"}},
		}},
		identityKeys: []hush.ExpiringIdentityKey{{
			IdentityKey: hush.IdentityKey{ResourceID: "k-123", Name: "ci secret", ExpiresAt: at(-time.Hour)},
			Identity:    hush.Identity{Fingerprint: "id1", NHIID: "nhi-i1", Name: "ci-app", NHIType: "Azure App"},
		}},
		deployments: map[string]string{"dep_1": "prod-eu"},
		polls:       map[string]pollState{},
	}, map[string]string{"team": "team:"})

	want := `
# HELP hush_certificate_expiration_timestamp_seconds When a certificate with an open Hush expiry issue expires.
# TYPE hush_certificate_expiration_timestamp_seconds gauge
hush_certificate_expiration_timestamp_seconds{deployment="prod-eu",issuer="R3",nhi_id="nhi-c1",subject_cn="api.example.com",team="payments"} 1791460800
# HELP hush_identity_key_expiration_timestamp_seconds When an identity key with an open Hush expiry issue expires.
# TYPE hush_identity_key_expiration_timestamp_seconds gauge
hush_identity_key_expiration_timestamp_seconds{identity="ci-app",identity_type="Azure App",key="ci secret",key_id="k-123",nhi_id="nhi-i1",team=""} 1791284400
`
	err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"hush_certificate_expiration_timestamp_seconds", "hush_identity_key_expiration_timestamp_seconds")
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
				{ID: "acr_wif", Name: "wif", Type: "aws_wif", Kind: "dynamic", CreatedAt: at(-time.Hour)},
			},
			Policies: []hush.AccessPolicy{
				{ID: "apl_pg", Name: "pg", AccessCredentialID: "acr_pg", CredentialType: "postgres",
					Status: ptr("ok"), CreatedAt: at(-10 * 24 * time.Hour), RotatedAt: ptr(at(-2 * time.Hour))},
				{ID: "apl_new", Name: "new", AccessCredentialID: "acr_pg", CredentialType: "postgres",
					Status: ptr("syncing"), CreatedAt: at(-time.Minute)},
				{ID: "apl_kv", Name: "kv", AccessCredentialID: "acr_kv", CredentialType: "kv", Status: ptr("ok"), CreatedAt: at(-time.Hour)},
				{ID: "apl_wif", Name: "wif", AccessCredentialID: "acr_wif", CredentialType: "aws_wif", Status: ptr("ok"), CreatedAt: at(-time.Hour)},
				{ID: "apl_off", Name: "off", AccessCredentialID: "acr_pg", CredentialType: "postgres", Status: ptr("disabled"), CreatedAt: at(-time.Hour)},
			},
		},
		polls: map[string]pollState{},
	}, nil)

	want := `
# HELP hush_access_policy_last_rotation_timestamp_seconds When the access policy's dynamic credential last rotated, or the policy was created if it never did.
# TYPE hush_access_policy_last_rotation_timestamp_seconds gauge
hush_access_policy_last_rotation_timestamp_seconds{credential_type="postgres",deployment="",policy="new",policy_id="apl_new"} 1791287940
hush_access_policy_last_rotation_timestamp_seconds{credential_type="postgres",deployment="",policy="pg",policy_id="apl_pg"} 1791280800
# HELP hush_access_credential_last_rotation_timestamp_seconds When an auto-rotated access credential's root last rotated, or it was created if it never did.
# TYPE hush_access_credential_last_rotation_timestamp_seconds gauge
hush_access_credential_last_rotation_timestamp_seconds{credential="mq",credential_id="acr_mq",credential_type="rabbitmq"} 1791201600
`
	err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"hush_access_policy_last_rotation_timestamp_seconds", "hush_access_credential_last_rotation_timestamp_seconds")
	if err != nil {
		t.Error(err)
	}

	// One series per status, set on the current one only.
	if n := testutil.CollectAndCount(c, "hush_access_policy_status"); n != 5*len(policyStatuses) {
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
# HELP hush_exporter_last_success_timestamp_seconds When the source was last read successfully.
# TYPE hush_exporter_last_success_timestamp_seconds gauge
hush_exporter_last_success_timestamp_seconds{source="certificates"} 1791287700
hush_exporter_last_success_timestamp_seconds{source="identity_keys"} 1791284400
`
	err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"hush_exporter_up", "hush_exporter_last_success_timestamp_seconds")
	if err != nil {
		t.Error(err)
	}
}

func TestDuplicateLabelsDoNotFailTheScrape(t *testing.T) {
	cert := hush.Certificate{ID: "c", ExpiresAt: ptr(at(time.Hour)), DeploymentIDs: []string{"d1", "d2"}}
	c := collector(snapshot{
		certificates: []hush.Certificate{cert},
		deployments:  map[string]string{"d1": "same", "d2": "same"},
		polls:        map[string]pollState{},
	}, nil)
	if err := testutil.CollectAndCompare(c, strings.NewReader(""), "none"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "hush_certificate_expiration_timestamp_seconds"); n != 1 {
		t.Errorf("series = %d, want 1", n)
	}
}

func TestTagLabelClash(t *testing.T) {
	for _, name := range []string{"identity", "deployment", "__name", "team-name"} {
		if _, err := NewCollector(&Poller{}, map[string]string{name: "x:"}); err == nil {
			t.Errorf("tag label %s accepted", name)
		}
	}
}
