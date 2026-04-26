# ELK Observability

The WAF writes structured JSON logs to the path configured by `log_path` (default: `debug.json` when set via Caddyfile, `log.json` when set as the `Provision` fallback). When `log_json` is enabled, every record is a one-line JSON object suitable for ingestion by Elasticsearch / Kibana via Filebeat.

![caddy-waf in Kibana](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/caddy-waf-elk.png?raw=true)

## Stack

This guide assumes a self-hosted ELK stack reachable from the WAF host. The reference stack used during development is [`deviantony/docker-elk`](https://github.com/deviantony/docker-elk):

```bash
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
docker compose up setup
docker compose up -d
```

After startup, Kibana is reachable at `http://<elk-host>:5601` (default credentials `elastic` / `changeme` — change them before exposing the stack).

## Filebeat

Install Filebeat on the host running Caddy:

```bash
# macOS
brew install filebeat

# Debian / Ubuntu
sudo apt install filebeat

# Alpine
sudo apk add filebeat
```

Replace the default `filebeat.yml` with the configuration below, adjusting the path to the WAF log file and the Elasticsearch host / credentials:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /path/to/caddy-waf/debug.json
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: message

output.elasticsearch:
  hosts: ["<elk-host>:9200"]
  username: "elastic"
  password: "<changeme>"
```

Reload Filebeat (`brew services restart filebeat`, `systemctl restart filebeat`, etc.).

## Verifying

In Kibana, open **Observability → Logs Explorer**. The `caddy-waf` records will appear with the structured fields emitted by `prepareLogFields` in [`logging.go`](../logging.go) — `log_id`, `source_ip`, `request_method`, `request_path`, `status_code`, `rule_id`, `total_score`, and so on.

A typical query for blocked requests:

```text
event.original : * AND status_code: 403 AND rule_id: *
```

A typical pivot for the noisiest rules:

```text
rule_id : *  | top 10 rule_id
```

## Notes

- Set `log_severity` to `info` (or higher) in production to keep Filebeat from shipping debug-level chatter.
- Sensitive query parameters and log fields are redacted before they reach the file when `redact_sensitive_data` is enabled.
- Because Filebeat tails the file, log rotation must be cooperative. Configure your log rotation tool (e.g. `logrotate`) to use `copytruncate` or send the rotated file's path back to Filebeat.
