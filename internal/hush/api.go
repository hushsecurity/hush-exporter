package hush

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var (
	certificateExpiryIssues = []string{"soon_expire_cert", "expired_cert"}
	identityKeyExpiryIssues = []string{"identity_key_soon_expire", "identity_key_expired"}
)

type Tag struct {
	Name string `json:"name"`
}

type Certificate struct {
	ID            string   `json:"id"`
	SubjectCN     string   `json:"subject_cn"`
	IssuerName    string   `json:"issuer_name"`
	ExpiresAt     *Time    `json:"expires_at"`
	DeploymentIDs []string `json:"deployment_ids"`
	Tags          []Tag    `json:"tags"`
}

func (c *Client) ExpiringCertificates(ctx context.Context) ([]Certificate, error) {
	return postAll[Certificate](ctx, c, "/v1/findings/certificates", []filter{
		{Name: "issue_type", Op: "eq", Values: certificateExpiryIssues},
		// archived: dismissed in Hush
		{Name: "cert_status", Op: "eq", Values: []string{"active"}},
	})
}

type Identity struct {
	Fingerprint string `json:"fingerprint"`
	NHIID       string `json:"nhi_id"`
	Name        string `json:"name"`
	NHIType     string `json:"nhi_type"`
	Tags        []Tag  `json:"tags"`
}

type IdentityKey struct {
	ResourceID string `json:"resource_id"` // the provider's key id
	Name       string `json:"name"`
	ExpiresAt  Time   `json:"expires_at"`
}

type ExpiringIdentityKey struct {
	IdentityKey
	Identity Identity
}

// Lists identities with an open expiry issue; their evidence names the keys.
func (c *Client) ExpiringIdentityKeys(ctx context.Context) ([]ExpiringIdentityKey, error) {
	identities, err := postAll[Identity](ctx, c, "/v1/findings/identities", []filter{
		{Name: "issue_type", Op: "eq", Values: identityKeyExpiryIssues},
	})
	if err != nil {
		return nil, err
	}
	flagged := make(map[string]bool, len(identities))
	var keys []ExpiringIdentityKey
	for _, id := range identities {
		flagged[id.Fingerprint] = true
		idKeys, err := c.identityKeys(ctx, id.Fingerprint)
		if err != nil {
			return nil, err
		}
		for _, key := range idKeys {
			keys = append(keys, ExpiringIdentityKey{IdentityKey: key, Identity: id})
		}
	}
	c.mu.Lock()
	for fp := range c.keys {
		if !flagged[fp] {
			delete(c.keys, fp)
		}
	}
	c.mu.Unlock()
	return keys, nil
}

// A key's expiry never changes; refetch daily only to catch a replaced key.
const keysMaxAge = 24 * time.Hour

type cachedKeys struct {
	keys []IdentityKey
	at   time.Time
}

func (c *Client) identityKeys(ctx context.Context, fp string) ([]IdentityKey, error) {
	c.mu.Lock()
	cached, ok := c.keys[fp]
	c.mu.Unlock()
	if ok && time.Since(cached.at) < keysMaxAge {
		return cached.keys, nil
	}
	var evidence struct {
		Items []IdentityKey `json:"items"`
	}
	body := map[string]string{"fp": fp}
	if err := c.do(ctx, http.MethodPost, "/v1/findings/issue/evidence/identity_key", body, &evidence); err != nil {
		return nil, fmt.Errorf("keys of %s: %w", fp, err)
	}
	c.mu.Lock()
	c.keys[fp] = cachedKeys{evidence.Items, time.Now()}
	c.mu.Unlock()
	return evidence.Items, nil
}

type AccessPolicy struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	AccessCredentialID string   `json:"access_credential_id"`
	DeploymentIDs      []string `json:"deployment_ids"`
	CredentialType     string   `json:"access_credential_type"`
	Status             *string  `json:"status"`
	CreatedAt          Time     `json:"created_at"`
	RotatedAt          *Time    `json:"rotated_at"`
}

func (c *Client) AccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	return getAll[AccessPolicy](ctx, c, "/v1/access_policies")
}

type AccessCredential struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	Kind           string  `json:"kind"`
	Status         *string `json:"status"`
	AutoRotateRoot bool    `json:"auto_rotate_root"`
	CreatedAt      Time    `json:"created_at"`
	RotatedAt      *Time   `json:"rotated_at"`
}

func (c *Client) AccessCredentials(ctx context.Context) ([]AccessCredential, error) {
	return getAll[AccessCredential](ctx, c, "/v1/access_credentials")
}

type SecretStore struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SecretStoreStatus struct {
	DeploymentID string `json:"deployment_id"`
	Status       string `json:"status"`
}

func (c *Client) SecretStores(ctx context.Context) ([]SecretStore, error) {
	return getAll[SecretStore](ctx, c, "/v1/secret_stores")
}

func (c *Client) SecretStoreStatuses(ctx context.Context, storeID string) ([]SecretStoreStatus, error) {
	var statuses []SecretStoreStatus
	path := "/v1/secret_stores/" + url.PathEscape(storeID) + "/deployment_statuses"
	if err := c.do(ctx, http.MethodGet, path, nil, &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

type Deployment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) Deployments(ctx context.Context) ([]Deployment, error) {
	return getAll[Deployment](ctx, c, "/v1/deployments")
}
