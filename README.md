# hush-exporter

Exposes Hush Security findings as Prometheus metrics, so you can alert on them
from the monitoring you already run.

It runs in your environment, reads the Hush API with a read-only API key, and
serves `/metrics` in the OpenMetrics format for Prometheus, or any scraper
that reads it, to collect.

> **Status: early.**

## What it reports

- Certificates about to expire, or expired
- Identity keys about to expire: Azure app secrets, GCP service account keys
- Access management: policy and credential status, last rotation
- Secret store health, per deployment

## How it works

The exporter reads the Hush API in the background and keeps the results in
memory. A scrape is served from that cache and never calls Hush, so scrape as
often as you like.

- Access management status: every 5 minutes
- Expiring certificates and identity keys: every hour
- A key's expiry and deployment names: fetched once, then daily

One exporter per Hush org is enough. Running one per cluster only repeats the
same data.

## Metrics

All metrics are gauges. Times are Unix timestamps in seconds; alert on them
against `time()`.

### Expiry

Only items with an open Hush expiry issue are exported. Hush decides what
counts as expiring from the item's lifetime; for certificates:

- valid for less than 14 days (e.g. auto-renewed by cert-manager): never
- valid for up to 90 days: 2 weeks before expiry
- valid for longer: 1 month before expiry
- expired: for 3 months after expiry

| Metric | Labels |
|---|---|
| `hush_certificate_expiration_timestamp_seconds` | `nhi_id`, `subject_cn`, `issuer`, `deployment` |
| `hush_identity_key_expiration_timestamp_seconds` | `nhi_id`, `identity`, `identity_type`, `key`, `key_id` |

`nhi_id` is the item's id in Hush; for an identity key, the identity's. `key_id`
is the provider's key id: the GCP key id or the Azure credential id.
Identity keys are Azure app secrets and GCP service account keys. AWS IAM
user access keys have no expiry, so they are not here.

### Access management

Status metrics carry one series per possible status, set to `1` for the
current one and `0` for the rest, so a series never disappears when the status
changes.

| Metric | Labels | Statuses |
|---|---|---|
| `hush_access_policy_status` | `policy_id`, `policy`, `credential_type`, `deployment`, `status` | `syncing`, `ok`, `warning`, `error`, `disabled` |
| `hush_access_policy_last_rotation_timestamp_seconds` | `policy_id`, `policy`, `credential_type`, `deployment` | |
| `hush_access_credential_status` | `credential_id`, `credential`, `credential_type`, `status` | `syncing`, `ok`, `warning`, `error` |
| `hush_access_credential_last_rotation_timestamp_seconds` | `credential_id`, `credential`, `credential_type` | |
| `hush_secret_store_status` | `secret_store_id`, `secret_store`, `deployment`, `status` | `pending`, `ready`, `warning`, `error` |

Rotation metrics are exported only where Hush rotates:

- a policy: when its credential is dynamic, other than WIF, and the policy
  is not disabled
- a credential: when `auto_rotate_root` is on

Until the first rotation they carry the creation time, so a rotation that never
happens still alerts.

### Exporter

| Metric | Labels | Meaning |
|---|---|---|
| `hush_exporter_up` | `source` | `1` if the last poll of `source` succeeded |
| `hush_exporter_last_success_timestamp_seconds` | `source` | When `source` was last read |

`source` is `certificates`, `identity_keys` or `access_management`.

### Example alerts

```yaml
- alert: HushCertificateExpiring
  expr: hush_certificate_expiration_timestamp_seconds - time() < 7 * 86400
- alert: HushPolicyRotationOverdue
  expr: time() - hush_access_policy_last_rotation_timestamp_seconds > 8 * 86400
- alert: HushPolicyError
  expr: hush_access_policy_status{status="error"} == 1
- alert: HushExporterDown
  expr: hush_exporter_up == 0
```

## Labels from Hush tags

Hush tags can become labels, so alerts route to the owning team. Map a label
to a tag prefix:

```yaml
tag_labels:
  team: "team:"
```

An item tagged `team:payments` then carries `team="payments"`. An item without
a matching tag carries `team=""`.

## Running

```sh
docker run -p 10057:10057 \
  -e HUSH_API_KEY_ID=... -e HUSH_API_KEY_SECRET=... -e HUSH_REALM=EU \
  ghcr.io/hushsecurity/hush-exporter
```

Then scrape it:

```yaml
scrape_configs:
  - job_name: hush
    static_configs:
      - targets: ["hush-exporter:10057"]
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HUSH_API_KEY_ID` | | API key id |
| `HUSH_API_KEY_SECRET` | | API key secret |
| `HUSH_REALM` | `US` | Your Hush region: `US` or `EU` |
| `HUSH_SOURCES` | all | Comma-separated: `certificates`, `identity_keys`, `access_management` |
| `HUSH_LISTEN_ADDRESS` | `:10057` | Where to serve metrics |
| `HUSH_BASE_URL` | | Overrides `HUSH_REALM` with an API URL |
| `HUSH_CONFIG_FILE` | | YAML with `tag_labels` |

The key and realm work as in the Hush Terraform provider.

### API key

Create the key in the org you want to monitor; a key from a parent org does
not see its sub-orgs' data. Give it only the privileges below, and neither
"all read" nor "all write":

- `analytics:read`
- `access_policies:read`
- `deployments:read`

With `HUSH_SOURCES`, fewer will do:

| Source | Privileges |
|---|---|
| `certificates` | `analytics:read` |
| `identity_keys` | `analytics:read` |
| `access_management` | `access_policies:read`, `deployments:read` |

Without `deployments:read`, `deployment` labels show ids instead of names.

A key with these privileges cannot read its own expiry. If the key expires or
is rotated, polls fail and `hush_exporter_up` drops to `0`; alert on that. A
rotated key stops working at once, so update the exporter's secret right after
rotating.

## Hush API used

| Data | Endpoint |
|---|---|
| Expiring certificates | `POST /v1/findings/certificates` |
| Expiring identity keys | `POST /v1/findings/identities`, and `POST /v1/findings/issue/evidence/identity_key` once per newly flagged identity |
| Policies | `GET /v1/access_policies` |
| Credentials | `GET /v1/access_credentials` |
| Deployment names | `GET /v1/deployments` |
| Secret stores | `GET /v1/secret_stores`, then `GET /v1/secret_stores/{id}/deployment_statuses` |
