# Splunk Integration

The platform exports findings as Splunk-ready events — CIM-friendly field
names (`dest`, `dest_port`, `severity`), `sourcetype` `secplatform:finding`,
one JSON object per line. Two ingest paths; both are operator-triggered
and audit-logged, and neither changes what the platform scans.

## Path 1: spool file (no Splunk credentials needed)

`POST /export/splunk` with `{"mode": "spool"}` (the default) appends all
matching findings as JSON Lines to:

```
data/splunk_spool/secplatform-<timestamp>.log
```

Point a Splunk Universal Forwarder at that directory:

```ini
# /opt/splunkforwarder/etc/system/local/inputs.conf
[monitor:///path/to/security-platform/data/splunk_spool]
sourcetype = secplatform:finding
index = security
```

Splunk ingests new files on its own schedule. This is the recommended
path: the platform never needs your Splunk credentials, and the forwarder
is Splunk's own supported mechanism for file ingestion.

## Path 2: HEC (HTTP Event Collector)

`POST /export/splunk` with `{"mode": "hec"}` POSTs newline-delimited
events to your HEC endpoint. Configure via environment variables only —
never in the repo or the config file:

```bash
export SPLUNK_HEC_URL="https://your-splunk:8088"
export SPLUNK_HEC_TOKEN="<hec-token>"
export SPLUNK_HEC_INDEX="security"        # optional
export SPLUNK_HEC_SOURCETYPE="secplatform:finding"  # optional override
```

To create the token in Splunk: **Settings → Data Inputs → HTTP Event
Collector → New Token**, note the token value, and enable the input.
If the variables are missing, the API returns 503 and the attempt is
audit-logged as denied.

## Filtering

Both paths accept the same filters as `GET /findings`:

```json
{"mode": "spool", "severity": "high", "status": "confirmed"}
```

Omit filters to export everything.

## Dashboard

The dashboard header has an **Export to Splunk** button with a mode
selector (spool file / HEC). The result line confirms how many events
were written or sent.

## Field reference

Each event is a HEC envelope:

```json
{
  "time": 1759252860.0,
  "source": "security-platform",
  "sourcetype": "secplatform:finding",
  "event": {
    "finding_id": "…",
    "dest": "10.0.0.12",
    "dest_port": 445,
    "target": "10.0.0.12",
    "title": "Open port 445/tcp",
    "severity": "medium",
    "status": "confirmed",
    "first_seen": "…",
    "last_seen": "…",
    "remediation": "…",
    "evidence_count": 2,
    "vendor_product": "security-platform"
  }
}
```

`dest_port` is present when a port could be determined from the
finding's evidence or title.

## Safety notes

- Export is read-only: it reads the local findings database and writes
  events. It never scans, probes, or contacts anything except the
  configured HEC endpoint.
- HEC tokens are secrets: keep them in environment variables, never in
  files that get committed.
- Every export (allowed or denied) is written to the immutable audit log
  as `export.splunk`.
