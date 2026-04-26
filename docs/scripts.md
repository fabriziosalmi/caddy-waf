# Helper Scripts

The repository ships a set of Python scripts that automate the creation and refresh of rule files and blacklists from external sources. None of the scripts are required at runtime — they exist to keep the bundled `rules.json`, `ip_blacklist.txt`, and `dns_blacklist.txt` up to date.

All scripts target Python 3 and use only the standard library plus `requests` (and, for some, `tqdm`).

## Inventory

| Script | Inputs | Output | Purpose |
|---|---|---|---|
| [`get_owasp_rules.py`](../get_owasp_rules.py) | OWASP Core Rule Set repository (`coreruleset/coreruleset`) on GitHub | `rules.json` (overwritten / appended) | Downloads OWASP CRS `.conf` files via the GitHub API, parses `SecRule` directives, and converts them into the WAF's JSON rule schema. |
| [`get_spiderlabs_rules.py`](../get_spiderlabs_rules.py) | Trustwave SpiderLabs ModSecurity rules | `rules.json` (overwritten / appended) | Same idea as the OWASP script, sourced from SpiderLabs. |
| [`get_vulnerability_rules.py`](../get_vulnerability_rules.py) | A built-in dictionary of CVE-style payloads | `rules.json` | Generates rules from a predefined payload table without any network calls. |
| [`get_blacklisted_ip.py`](../get_blacklisted_ip.py) | Emerging Threats, CI Army, IPsum, BlockList.de, Greensnow, Tor exit-address feed | `ip_blacklist.txt` | Downloads multiple IP feeds, merges them, deduplicates, and writes one IP/CIDR per line. |
| [`get_blacklisted_dns.py`](../get_blacklisted_dns.py) | Phishing-Angriffe, ShadowWhisperer Malware, StevenBlack hosts, hostsVN, durablenapkin scamblocklist, hagezi DNS blocklists, blackbook, [`fabriziosalmi/blacklists`](https://github.com/fabriziosalmi/blacklists) | `dns_blacklist.txt` | Downloads multiple domain feeds, merges and deduplicates them. |
| [`get_caddy_feeds.py`](../get_caddy_feeds.py) | Latest release of [`fabriziosalmi/caddy-feeds`](https://github.com/fabriziosalmi/caddy-feeds) | `ip_blacklist.txt`, `dns_blacklist.txt`, `rules.json` | Convenience: pulls all three feeds in one shot from a curated bundle. |

## Common requirements

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests tqdm
```

All scripts require outbound HTTPS access to their respective sources.

## Usage

### `get_owasp_rules.py`

Edit the constants at the top of the script (repo URL, rules directory, output path) if you want a non-default location. Run:

```bash
python3 get_owasp_rules.py
```

Notes:

- The script uses the unauthenticated GitHub API. For large repositories you may hit rate limits (60 requests/hour per IP); add a `GITHUB_TOKEN` to the `headers` dictionary if needed.
- The conversion from ModSecurity `SecRule` to the WAF JSON schema is heuristic. Validate the output before deploying — some rules may need manual touch-ups.

### `get_spiderlabs_rules.py`

```bash
python3 get_spiderlabs_rules.py
```

Same characteristics as the OWASP script.

### `get_vulnerability_rules.py`

```bash
python3 get_vulnerability_rules.py
```

No network access required — the rules come from the in-script payload dictionary. Edit the dictionary to add or remove categories.

### `get_blacklisted_ip.py`

```bash
python3 get_blacklisted_ip.py
```

The script writes IPv4 addresses and CIDR ranges, one per line. Tor exit nodes are pulled from `https://check.torproject.org/exit-addresses`. Review the output before deploying — these feeds occasionally include legitimate addresses.

### `get_blacklisted_dns.py`

```bash
python3 get_blacklisted_dns.py
```

The script lower-cases all entries and writes one domain per line, deduplicated. The output is suitable for use as `dns_blacklist_file` directly.

### `get_caddy_feeds.py`

> The script's own header reads: *"TESTING! Do not use on live services, even if at home :)"*. Treat it as opt-in and review the downloaded files before deploying them.

```bash
python3 get_caddy_feeds.py
```

It downloads all three resources from the latest release of the upstream repo into the current working directory.

## Scheduling

To keep blacklists fresh, schedule the scripts with `cron` or systemd timers. Reload the WAF after each run by writing the updated file in place — `fsnotify` will pick up the change automatically.

```cron
# Refresh blacklists every six hours
0 */6 * * * cd /etc/caddy && /usr/bin/python3 get_blacklisted_ip.py  >> /var/log/caddy/ip-feed.log  2>&1
0 */6 * * * cd /etc/caddy && /usr/bin/python3 get_blacklisted_dns.py >> /var/log/caddy/dns-feed.log 2>&1

# Refresh rules nightly
30 3 * * *  cd /etc/caddy && /usr/bin/python3 get_owasp_rules.py     >> /var/log/caddy/owasp.log    2>&1
```

When the script writes a new `ip_blacklist.txt` or `dns_blacklist.txt` over the file pointed to by the corresponding `*_file` directive, the file watcher fires and the WAF rebuilds the prefix trie / DNS map atomically (see [dynamicupdates.md](dynamicupdates.md)).

## Operational notes

- Always validate the generated `rules.json` with `jq . rules.json > /dev/null` before letting the WAF reload it; an invalid JSON file fails the reload and the previous rules remain in effect.
- Keep generated files in a separate directory (e.g. `/etc/caddy/feeds/`) and reference them from the Caddyfile. Mixing generated and hand-authored rules in the same file invites accidental overwrites.
- For air-gapped environments, run the scripts on a connected host and copy the outputs over.
