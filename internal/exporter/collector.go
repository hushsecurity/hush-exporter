package exporter

import (
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hushsecurity/hush-exporter/internal/hush"
)

// Every status a series can take, so that each one always has a series and a
// change of status never makes one disappear.
var (
	policyStatuses      = []string{"syncing", "ok", "warning", "error", "disabled"}
	credentialStatuses  = []string{"syncing", "ok", "warning", "error"}
	secretStoreStatuses = []string{"pending", "ready", "warning", "error"}
)

// Collector turns the poller's last read into metrics, computing ages at
// scrape time.
type Collector struct {
	poller *Poller
	// Label name to the tag prefix it is read from, e.g. team: "team:".
	tagLabels map[string]string
	tagNames  []string
	now       func() time.Time

	certificateExpiry  *prometheus.Desc
	identityKeyExpiry  *prometheus.Desc
	policyStatus       *prometheus.Desc
	policyRotation     *prometheus.Desc
	credentialStatus   *prometheus.Desc
	credentialRotation *prometheus.Desc
	secretStoreStatus  *prometheus.Desc
	up                 *prometheus.Desc
	sinceSuccess       *prometheus.Desc
}

func NewCollector(poller *Poller, tagLabels map[string]string) *Collector {
	tagNames := make([]string, 0, len(tagLabels))
	for name := range tagLabels {
		tagNames = append(tagNames, name)
	}
	sort.Strings(tagNames)
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, labels, nil)
	}
	tagged := func(labels ...string) []string { return append(labels, tagNames...) }
	return &Collector{
		poller:    poller,
		tagLabels: tagLabels,
		tagNames:  tagNames,
		now:       time.Now,

		certificateExpiry: desc("hush_certificate_expires_in_seconds",
			"Time until a certificate with an open Hush expiry issue expires; negative once expired.",
			tagged("fingerprint", "subject_cn", "issuer", "deployment", "severity")...),
		identityKeyExpiry: desc("hush_identity_key_expires_in_seconds",
			"Time until an identity key with an open Hush expiry issue expires; negative once expired.",
			tagged("key_id", "key", "identity", "identity_fingerprint", "identity_type", "severity")...),
		policyStatus: desc("hush_access_policy_status",
			"1 for the access policy's current status, 0 for the others.",
			"policy_id", "policy", "credential_type", "status"),
		policyRotation: desc("hush_access_policy_seconds_since_rotation",
			"Time since the access policy's dynamic credential last rotated, or since the policy was created if it never did.",
			"policy_id", "policy", "credential_type"),
		credentialStatus: desc("hush_access_credential_status",
			"1 for the access credential's current status, 0 for the others.",
			"credential_id", "credential", "credential_type", "kind", "status"),
		credentialRotation: desc("hush_access_credential_seconds_since_rotation",
			"Time since an auto-rotated access credential's root last rotated, or since it was created if it never did.",
			"credential_id", "credential", "credential_type"),
		secretStoreStatus: desc("hush_secret_store_status",
			"1 for the secret store's current status on a deployment, 0 for the others.",
			"secret_store_id", "secret_store", "deployment", "status"),
		up: desc("hush_exporter_up",
			"1 if the last poll of the source succeeded.", "source"),
		sinceSuccess: desc("hush_exporter_seconds_since_success",
			"Age of the data read from the source.", "source"),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.certificateExpiry, c.identityKeyExpiry, c.policyStatus, c.policyRotation,
		c.credentialStatus, c.credentialRotation, c.secretStoreStatus, c.up, c.sinceSuccess,
	} {
		ch <- d
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s := c.poller.snapshot()
	now := c.now()
	// Two items can share their labels, e.g. two deployments with one name.
	// Keep the first: a duplicate series fails the whole scrape.
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
		severity := ""
		if cert.Severity != nil {
			severity = *cert.Severity
		}
		deployments := cert.DeploymentIDs
		if len(deployments) == 0 {
			deployments = []string{""}
		}
		// A certificate found on several deployments alerts on each.
		for _, d := range deployments {
			gauge(c.certificateExpiry, cert.ExpiresAt.Sub(now).Seconds(),
				c.withTags(cert.Tags, cert.Fingerprint, cert.SubjectCN, cert.IssuerName, deployment(d), severity)...)
		}
	}

	for _, key := range s.identityKeys {
		id := key.Identity
		gauge(c.identityKeyExpiry, key.ExpiresAt.Sub(now).Seconds(),
			c.withTags(id.Tags, key.KeyID, key.Name, id.NHIName, id.Fingerprint, id.NHIType, id.Severity)...)
	}

	am := s.accessManagement
	dynamic := map[string]bool{}
	for _, cred := range am.Credentials {
		dynamic[cred.ID] = cred.Kind == "dynamic"
		stateSet(gauge, c.credentialStatus, credentialStatuses, cred.Status,
			cred.ID, cred.Name, cred.Type, cred.Kind)
		if cred.AutoRotateRoot {
			gauge(c.credentialRotation, since(now, cred.RotatedAt, cred.CreatedAt),
				cred.ID, cred.Name, cred.Type)
		}
	}
	for _, apl := range am.Policies {
		stateSet(gauge, c.policyStatus, policyStatuses, apl.Status,
			apl.ID, apl.Name, apl.CredentialType)
		// A policy over a static credential hands out the credential as is.
		if dynamic[apl.AccessCredentialID] {
			gauge(c.policyRotation, since(now, apl.RotatedAt, apl.CreatedAt),
				apl.ID, apl.Name, apl.CredentialType)
		}
	}
	for _, store := range am.Stores {
		for _, st := range store.Statuses {
			status := st.Status
			stateSet(gauge, c.secretStoreStatus, secretStoreStatuses, &status,
				store.ID, store.Name, deployment(st.DeploymentID))
		}
	}

	for _, source := range sources {
		state := s.polls[source]
		up := 0.0
		if state.up {
			up = 1
		}
		gauge(c.up, up, source)
		if !state.lastSuccess.IsZero() {
			gauge(c.sinceSuccess, now.Sub(state.lastSuccess).Seconds(), source)
		}
	}
}

// stateSet emits one series per possible status, 1 for the current one. An
// unknown status, or none, sets them all to 0.
func stateSet(gauge func(*prometheus.Desc, float64, ...string), d *prometheus.Desc, statuses []string, current *string, labels ...string) {
	for _, status := range statuses {
		v := 0.0
		if current != nil && *current == status {
			v = 1
		}
		gauge(d, v, append(labels, status)...)
	}
}

func since(now time.Time, at *hush.Time, fallback hush.Time) float64 {
	if at != nil {
		return now.Sub(at.Time).Seconds()
	}
	return now.Sub(fallback.Time).Seconds()
}

// withTags appends a value for each tag label: the rest of the first tag that
// starts with its prefix, or "".
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
