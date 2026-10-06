# hush-exporter

Exposes Hush Security findings as Prometheus / OpenMetrics metrics, so you can
alert on them from the monitoring you already run.

It runs in your environment, reads the Hush API with a read-only API key, and
serves `/metrics` for your Prometheus server or Datadog agent to scrape.

> **Status: early.** Not yet tried against a live Hush org.

## What it reports

- Certificates about to expire, or expired
- Identity keys about to expire: Azure app secrets, GCP service account keys
- Access management: policy and credential status, time since last rotation
- Secret store health, per deployment

## How it works

The exporter polls the Hush API on a timer (`HUSH_POLL_INTERVAL`, default
15m) and keeps the results in memory. A scrape is served from that cache and
never calls Hush, so scraping every 15s costs Hush nothing.

Ages and countdowns are computed at scrape time from the cached timestamps, so
they stay exact between polls. They are exported as plain values, not
timestamps, because Datadog monitors cannot subtract a value from now.

## Metrics

All metrics are gauges.

### Expiry

Only items with an open Hush expiry issue are exported. Hush decides what
counts as expiring from the item's lifetime; for certificates:

- valid for less than 14 days (e.g. auto-renewed by cert-manager): never
- valid for up to 90 days: 2 weeks before expiry
- valid for longer: 1 month before expiry
- expired: for 3 months after expiry

The value is the time left, negative once expired. Alert on your own threshold
on top of it, e.g. `< 7d`.

| Metric | Labels |
|---|---|
| `hush_certificate_expires_in_seconds` | `fingerprint`, `subject_cn`, `issuer`, `deployment`, `severity` |
| `hush_identity_key_expires_in_seconds` | `key_id`, `key`, `identity`, `identity_fingerprint`, `identity_type`, `severity` |

Identity keys are Azure app secrets and GCP service account keys. AWS IAM
user access keys have no expiry, so they are not here.

### Access management

Status metrics carry one series per possible status, set to `1` for the
current one and `0` for the rest, so a series never disappears when the status
changes.

| Metric | Labels | Statuses |
|---|---|---|
| `hush_access_policy_status` | `policy_id`, `policy`, `credential_type`, `status` | `syncing`, `ok`, `warning`, `error`, `disabled` |
| `hush_access_policy_seconds_since_rotation` | `policy_id`, `policy`, `credential_type` | |
| `hush_access_credential_status` | `credential_id`, `credential`, `credential_type`, `kind`, `status` | `syncing`, `ok`, `warning`, `error` |
| `hush_access_credential_seconds_since_rotation` | `credential_id`, `credential`, `credential_type` | |
| `hush_secret_store_status` | `secret_store_id`, `secret_store`, `deployment`, `status` | `pending`, `ready`, `warning`, `error` |

Rotation metrics are exported only where Hush rotates:

- a policy: when its credential is dynamic
- a credential: when `auto_rotate_root` is on

Until the first rotation, the age counts from creation, so a rotation that
never happens still alerts.

### Exporter

| Metric | Labels | Meaning |
|---|---|---|
| `hush_exporter_up` | `source` | `1` if the last poll of `source` succeeded |
| `hush_exporter_seconds_since_success` | `source` | Age of the cached data from `source` |

`source` is `certificates`, `identity_keys` or `access_management`.

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

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HUSH_API_KEY_ID` | | API key id |
| `HUSH_API_KEY_SECRET` | | API key secret |
| `HUSH_REALM` | `US` | Your Hush region: `US` or `EU` |
| `HUSH_POLL_INTERVAL` | `15m` | How often to read the Hush API |
| `HUSH_LISTEN_ADDRESS` | `:10057` | Where to serve metrics |
| `HUSH_BASE_URL` | | Overrides `HUSH_REALM` with an API URL |
| `HUSH_CONFIG_FILE` | | YAML with `tag_labels` and filters |

The key and realm work as in the Hush Terraform provider.

### API key

Create a key with only these privileges, and neither "all read" nor "all
write":

- `analytics:read`
- `access_policies:read`
- `deployments:read`

The exporter exchanges it for a short-lived token at `POST /v1/oauth/token`
and renews the token before it expires.

A key with these privileges cannot read its own expiry. If the key expires or
is rotated, polls fail and `hush_exporter_up` drops to `0`; alert on that. A
rotated key stops working at once, so update the exporter's secret right after
rotating.

## Datadog

The Datadog agent scrapes the exporter with its OpenMetrics check. With
autodiscovery, annotate the exporter's pod:

```yaml
ad.datadoghq.com/hush-exporter.checks: |
  {
    "openmetrics": {
      "instances": [
        {
          "openmetrics_endpoint": "http://%%host%%:10057/metrics",
          "namespace": "hush",
          "metrics": [".*"]
        }
      ]
    }
  }
```

## Hush API used

| Data | Endpoint |
|---|---|
| Expiring certificates | `POST /v1/findings/certificates`, filtered by issue type `soon_expire_cert`, `expired_cert` |
| Expiring identity keys | `POST /v1/findings/issues` (`identity_key_soon_expire`, `identity_key_expired`, open), then `POST /v1/findings/issue/evidence/identity_key` per identity |
| Policies | `GET /v1/access_policies` |
| Credentials | `GET /v1/access_credentials` |
| Deployment names | `GET /v1/deployments` |
| Secret stores | `GET /v1/secret_stores`, then `GET /v1/secret_stores/{id}/deployment_statuses` |

## Open questions

- Certificate filter: confirm `issue_types` on certificates drops resolved
  and ignored issues.
- Port: claim 10057 on the Prometheus default port allocations page.
- Owner labels from k8s workload labels, once the Hush workload API returns
  them.
