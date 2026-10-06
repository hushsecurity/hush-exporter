package hush

import (
	"context"
	"fmt"
	"net/http"
)

// Expiry issues: Hush opens them from the item's lifetime, so a certificate
// renewed every few days never gets one.
var (
	certificateExpiryIssues = []string{"soon_expire_cert", "expired_cert"}
	identityKeyExpiryIssues = []string{"identity_key_soon_expire", "identity_key_expired"}
	// Every triage status but resolved and ignored.
	openIssueStatuses = []string{"open", "in_progress", "reopened"}
)

type Tag struct {
	Name string `json:"name"`
}

type Certificate struct {
	Fingerprint   string   `json:"fingerprint"`
	SubjectCN     string   `json:"subject_cn"`
	IssuerName    string   `json:"issuer_name"`
	ExpiresAt     *Time    `json:"expires_at"`
	DeploymentIDs []string `json:"deployment_ids"`
	Severity      *string  `json:"severity"`
	Tags          []Tag    `json:"tags"`
}

// ExpiringCertificates lists the certificates with an expiry issue.
func (c *Client) ExpiringCertificates(ctx context.Context) ([]Certificate, error) {
	return postAll[Certificate](ctx, c, "/v1/findings/certificates", []Filter{
		{Name: "issue_type", Op: "eq", Values: certificateExpiryIssues},
	})
}

type Issue struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	NHIName     string `json:"nhi_name"`
	NHIType     string `json:"nhi_type"`
	Severity    string `json:"severity"`
	Tags        []Tag  `json:"tags"`
}

type IdentityKey struct {
	KeyID     string `json:"key_id"`
	Name      string `json:"name"`
	ExpiresAt Time   `json:"expires_at"`
}

// ExpiringIdentityKey is a key that is about to expire, or has, with the
// identity it signs in as.
type ExpiringIdentityKey struct {
	IdentityKey
	Identity Issue
}

// ExpiringIdentityKeys lists the keys of the identities with an open expiry
// issue. The issue names the identity; its evidence names the keys.
func (c *Client) ExpiringIdentityKeys(ctx context.Context) ([]ExpiringIdentityKey, error) {
	issues, err := postAll[Issue](ctx, c, "/v1/findings/issues", []Filter{
		{Name: "issue_type", Op: "eq", Values: identityKeyExpiryIssues},
		{Name: "status", Op: "eq", Values: openIssueStatuses},
	})
	if err != nil {
		return nil, err
	}
	var keys []ExpiringIdentityKey
	for _, issue := range issues {
		var evidence struct {
			Items []IdentityKey `json:"items"`
		}
		body := map[string]string{"fp": issue.Fingerprint}
		path := "/v1/findings/issue/evidence/identity_key"
		if err := c.do(ctx, http.MethodPost, path, body, &evidence); err != nil {
			return nil, fmt.Errorf("keys of %s: %w", issue.Fingerprint, err)
		}
		for _, key := range evidence.Items {
			keys = append(keys, ExpiringIdentityKey{IdentityKey: key, Identity: issue})
		}
	}
	return keys, nil
}

type AccessPolicy struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	AccessCredentialID string  `json:"access_credential_id"`
	CredentialType     string  `json:"access_credential_type"`
	Status             *string `json:"status"`
	CreatedAt          Time    `json:"created_at"`
	RotatedAt          *Time   `json:"rotated_at"`
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

// SecretStoreStatuses is a store's status on each of its deployments.
func (c *Client) SecretStoreStatuses(ctx context.Context, storeID string) ([]SecretStoreStatus, error) {
	var statuses []SecretStoreStatus
	path := "/v1/secret_stores/" + storeID + "/deployment_statuses"
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
