package exporter

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hushsecurity/hush-exporter/internal/hush"
)

// All statuses, so a status change never drops a series.
var (
	policyStatuses      = []string{"syncing", "ok", "warning", "error", "disabled"}
	credentialStatuses  = []string{"syncing", "ok", "warning", "error"}
	secretStoreStatuses = []string{"pending", "ready", "warning", "error"}
)

type Collector struct {
	poller    *Poller
	tagLabels map[string]string
	tagNames  []string

	certificateExpiry  *prometheus.Desc
	identityKeyExpiry  *prometheus.Desc
	policyStatus       *prometheus.Desc
	policyRotation     *prometheus.Desc
	credentialStatus   *prometheus.Desc
	credentialRotation *prometheus.Desc
	secretStoreStatus  *prometheus.Desc
	up                 *prometheus.Desc
	lastSuccess        *prometheus.Desc
}

var (
	labelName         = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	certificateLabels = []string{"nhi_id", "subject_cn", "issuer", "deployment"}
	identityKeyLabels = []string{"nhi_id", "identity", "identity_type", "key", "key_id"}
)

func NewCollector(poller *Poller, tagLabels map[string]string) (*Collector, error) {
	tagNames := make([]string, 0, len(tagLabels))
	for name, prefix := range tagLabels {
		switch {
		case !labelName.MatchString(name) || strings.HasPrefix(name, "__"):
			return nil, fmt.Errorf("tag_labels: %q is not a label name", name)
		case slices.Contains(certificateLabels, name) || slices.Contains(identityKeyLabels, name):
			return nil, fmt.Errorf("tag_labels: %s is a reserved label", name)
		case prefix == "":
			return nil, fmt.Errorf("tag_labels: %s needs a prefix", name)
		}
		tagNames = append(tagNames, name)
	}
	sort.Strings(tagNames)
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, labels, nil)
	}
	tagged := func(labels []string) []string { return append(slices.Clone(labels), tagNames...) }
	return &Collector{
		poller:    poller,
		tagLabels: tagLabels,
		tagNames:  tagNames,

		certificateExpiry: desc("hush_certificate_expiration_timestamp_seconds",
			"When a certificate with an open Hush expiry issue expires.",
			tagged(certificateLabels)...),
		identityKeyExpiry: desc("hush_identity_key_expiration_timestamp_seconds",
			"When an identity key with an open Hush expiry issue expires.",
			tagged(identityKeyLabels)...),
		policyStatus: desc("hush_access_policy_status",
			"1 for the access policy's current status, 0 for the others.",
			"policy_id", "policy", "credential_type", "deployment", "status"),
		policyRotation: desc("hush_access_policy_last_rotation_timestamp_seconds",
			"When the access policy's dynamic credential last rotated, or the policy was created if it never did.",
			"policy_id", "policy", "credential_type", "deployment"),
		credentialStatus: desc("hush_access_credential_status",
			"1 for the access credential's current status, 0 for the others.",
			"credential_id", "credential", "credential_type", "status"),
		credentialRotation: desc("hush_access_credential_last_rotation_timestamp_seconds",
			"When an auto-rotated access credential's root last rotated, or it was created if it never did.",
			"credential_id", "credential", "credential_type"),
		secretStoreStatus: desc("hush_secret_store_status",
			"1 for the secret store's current status on a deployment, 0 for the others.",
			"secret_store_id", "secret_store", "deployment", "status"),
		up: desc("hush_exporter_up",
			"1 if the last poll of the source succeeded.", "source"),
		lastSuccess: desc("hush_exporter_last_success_timestamp_seconds",
			"When the source was last read successfully.", "source"),
	}, nil
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.certificateExpiry, c.identityKeyExpiry, c.policyStatus, c.policyRotation,
		c.credentialStatus, c.credentialRotation, c.secretStoreStatus, c.up, c.lastSuccess,
	} {
		ch <- d
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s := c.poller.snapshot()
	// A duplicate series fails the whole scrape.
	seen := map[string]bool{}
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		key := d.String() + "\xff" + strings.Join(labels, "\xff")
		if seen[key] {
			return
		}
		seen[key] = true
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	deployment := func(id string) string {
		if name := s.deployments[id]; name != "" {
			return name
		}
		return id
	}

	for _, cert := range s.certificates {
		if cert.ExpiresAt == nil {
			continue
		}
		deployments := cert.DeploymentIDs
		if len(deployments) == 0 {
			deployments = []string{""}
		}
		for _, d := range deployments {
			gauge(c.certificateExpiry, unix(cert.ExpiresAt.Time),
				c.withTags(cert.Tags, cert.ID, cert.SubjectCN, cert.IssuerName, deployment(d))...)
		}
	}

	for _, key := range s.identityKeys {
		id := key.Identity
		gauge(c.identityKeyExpiry, unix(key.ExpiresAt.Time),
			c.withTags(id.Tags, id.NHIID, id.Name, id.NHIType, key.Name, key.ResourceID)...)
	}

	am := s.accessManagement
	dynamic := map[string]bool{}
	for _, cred := range am.Credentials {
		dynamic[cred.ID] = cred.Kind == "dynamic"
		stateSet(gauge, c.credentialStatus, credentialStatuses, cred.Status,
			cred.ID, cred.Name, cred.Type)
		if cred.AutoRotateRoot {
			gauge(c.credentialRotation, rotated(cred.RotatedAt, cred.CreatedAt),
				cred.ID, cred.Name, cred.Type)
		}
	}
	for _, apl := range am.Policies {
		dep := ""
		if len(apl.DeploymentIDs) > 0 { // at most one
			dep = deployment(apl.DeploymentIDs[0])
		}
		stateSet(gauge, c.policyStatus, policyStatuses, apl.Status,
			apl.ID, apl.Name, apl.CredentialType, dep)
		if rotates(apl, dynamic[apl.AccessCredentialID]) {
			gauge(c.policyRotation, rotated(apl.RotatedAt, apl.CreatedAt),
				apl.ID, apl.Name, apl.CredentialType, dep)
		}
	}
	for _, store := range am.Stores {
		for _, st := range store.Statuses {
			status := st.Status
			stateSet(gauge, c.secretStoreStatus, secretStoreStatuses, &status,
				store.ID, store.Name, deployment(st.DeploymentID))
		}
	}

	for _, source := range c.poller.enabled {
		state := s.polls[source]
		up := 0.0
		if state.up {
			up = 1
		}
		gauge(c.up, up, source)
		if !state.lastSuccess.IsZero() {
			gauge(c.lastSuccess, unix(state.lastSuccess), source)
		}
	}
}

func rotates(apl hush.AccessPolicy, dynamic bool) bool {
	// WIF has no rotation interval in midgard.
	if !dynamic || strings.HasSuffix(apl.CredentialType, "_wif") {
		return false
	}
	return apl.Status == nil || *apl.Status != "disabled"
}

func stateSet(gauge func(*prometheus.Desc, float64, ...string), d *prometheus.Desc, statuses []string, current *string, labels ...string) {
	for _, status := range statuses {
		v := 0.0
		if current != nil && *current == status {
			v = 1
		}
		gauge(d, v, append(labels, status)...)
	}
}

func rotated(at *hush.Time, created hush.Time) float64 {
	if at != nil {
		return unix(at.Time)
	}
	return unix(created.Time)
}

func unix(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }

func (c *Collector) withTags(tags []hush.Tag, labels ...string) []string {
	for _, name := range c.tagNames {
		prefix := c.tagLabels[name]
		value := ""
		for _, tag := range tags {
			if v, ok := strings.CutPrefix(tag.Name, prefix); ok {
				value = v
				break
			}
		}
		labels = append(labels, value)
	}
	return labels
}
