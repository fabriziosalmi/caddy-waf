# Helper Scripts

The repository ships a set of Python scripts that automate the creation and refresh of rule files and blacklists from external sources. None of the scripts are required at runtime — they exist to keep the bundled `rules.json`, `ip_blacklist.txt`, and `dns_blacklist.txt` up to date.

All scripts target Python 3 and use only the standard library plus `requests` (and, for some, `tqdm`).

## Inventory

| Script | Inputs | Output | Purpose |
|---|---|---|---|
| [`get_owasp_rules.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_owasp_rules.py) | An OWASP Core Rule Set release tarball (`coreruleset/coreruleset`, default `v4.9.0`) or a local `rules/` checkout | `rules/crs/crs-pl{1..4}.json`, `crs-pl{N}-response.json`, `COVERAGE.md` | SecLang → caddy-waf translator. Parses `SecRule` directives (continuations, chains, quoted actions), ports the `@rx`/`@pm`/`@pmFromFile` rules, maps variables to targets and `t:` chains to `transformations`, validates every pattern with Go's RE2, and writes a coverage report of what was skipped and why. |
| [`get_spiderlabs_rules.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_spiderlabs_rules.py) | Trustwave SpiderLabs ModSecurity rules | `spiderlabs_rules.json` | Same idea as the OWASP script, sourced from SpiderLabs. Keeps only `@rx` (regex) rules and strips the operator, so the output compiles under RE2; non-regex operators are skipped. |
| [`get_vulnerability_rules.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_vulnerability_rules.py) | A built-in dictionary of CVE-style payloads | `rules.json` | Generates rules from a predefined payload table without any network calls. |
| [`get_blacklisted_ip.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_blacklisted_ip.py) | Emerging Threats, CI Army, IPsum, BlockList.de, Greensnow, NetAPI, Tor exit-address feed | `ip_blacklist.txt` | Downloads multiple IP feeds, merges them, deduplicates, and writes one IP/CIDR per line. |
| [`get_blacklisted_dns.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_blacklisted_dns.py) | Phishing-Angriffe, ShadowWhisperer Malware, StevenBlack hosts, hostsVN, durablenapkin scamblocklist, hagezi DNS blocklists, blackbook, [`fabriziosalmi/blacklists`](https://github.com/fabriziosalmi/blacklists) | `dns_blacklist.txt` | Downloads multiple domain feeds, merges and deduplicates them. |
| [`get_caddy_feeds.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_caddy_feeds.py) | Latest release of [`fabriziosalmi/caddy-feeds`](https://github.com/fabriziosalmi/caddy-feeds) | `ip_blacklist.txt`, `dns_blacklist.txt`, `rules.json` | Convenience: pulls all three feeds in one shot from a curated bundle. |

## Common requirements

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests tqdm
```

All scripts require outbound HTTPS access to their respective sources.

## Usage

### `get_owasp_rules.py`

```bash
# One request bundle per paranoia level, downloading the CRS v4.9.0 tarball from GitHub:
python3 get_owasp_rules.py --ref v4.9.0 --output-dir rules/crs

# One cumulative file up to paranoia level 2, from a local CRS checkout:
python3 get_owasp_rules.py --source ~/src/coreruleset/rules --paranoia-level 2 \
    --output /etc/caddy/crs-pl2.json --report /etc/caddy/crs-coverage.md
```

| Option | Meaning |
|---|---|
| `--ref TAG` / `--source DIR` | CRS git tag to download (default `v4.9.0`), or a local `rules/` directory (no network; `--ref` then only labels the report). |
| `--output-dir DIR` | One request bundle per paranoia level (`crs-pl1.json` … `crs-pl4.json`) plus `crs-plN-response.json` for the phase 3/4 rules. |
| `--output FILE --paranoia-level N` | One cumulative request bundle up to level N; response rules go to `FILE-response.json`. |
| `--tuning FILE` | Per-rule adjustments, one per line: `<id> remove` drops a rule, `<id> remove-target BODY` keeps it off one target. `#` comments are copied into the report as the reason. |
| `--exclude 920350,920440` | Ad hoc rule removal without a tuning file. |
| `--block-severity CRITICAL` | Emit `"action": "block"` for rules at or above that severity. Default: every rule is `log` (advisory). |
| `--re2check go\|python\|auto` | Pattern validator. `go` runs `go run ./tools/re2check` so patterns are compiled by the same `regexp` package caddy-waf uses and fails if that is not possible; `python` is a syntax heuristic (lookaround, backreferences) for machines without Go; `auto` (default) uses Go when the helper and toolchain are available and warns and falls back otherwise, e.g. when the script has been copied out of the repository. |
| `--report FILE` | Where to write the coverage report (default `COVERAGE.md` next to the output). |

What gets ported, and what does not:

- Ported: `@rx` rules as-is; `@pm`/`@pmFromFile` keyword lists as a case-insensitive alternation (sorted so Go can factor common prefixes; unsorted lists are 10–20× slower to match); `t:` chains mapped onto the engine's `transformations` (unsupported steps such as `cmdLine` and `jsDecode` are dropped with a note, `removeWhitespace` is approximated by `compressWhitespace`); CRS variables mapped onto targets (`ARGS` → `ARGS` + `BODY`, `REQUEST_HEADERS:Host` → `HOST`, `XML` → `BODY`, …); severity → score (CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2); the `paranoia-level/N` tag → output file.
- Skipped, and listed in the report with the reason: chained rules, every non-regex operator (`@detectSQLi`, `@validateByteRange`, `@eq`, …), control-flow rules without a severity, `^$` presence checks (this engine skips a rule whose target is empty), rules whose only variables have no equivalent (`TX`, `&ARGS`, `MULTIPART_*`), rules that need `base64Decode`/`length`/`sha1`, and anything RE2 rejects.
- A leading `^` or trailing `$` on a collection target (`ARGS`, `BODY`, `HEADERS`, `COOKIES`) is rewritten to a member boundary, because ModSecurity matches each value on its own while caddy-waf matches the whole query string / header list.

The result is CRS-informed coverage, not CRS parity: the generated `COVERAGE.md` lists the gaps that matter (libinjection, chained rules, parsed parameters), and the [OWASP CRS section of `rules/README.md`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/README.md#owasp-crs) covers loading the output. Unit tests: `python3 -m unittest test_get_owasp_rules`.

### `get_spiderlabs_rules.py`

```bash
python3 get_spiderlabs_rules.py
```

Writes `spiderlabs_rules.json`. Only CRS `@rx` (regex) rules are kept — the `@rx` operator is stripped so each pattern is a bare RE2 regex — and non-regex operators (`@detectSQLi`, `@pmFromFile`, `@eq`, …) are skipped, since caddy-waf matches with Go's RE2, not the ModSecurity operator engine. Point `rule_file` at the output to use it; validate before deploying.

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

# Refresh the CRS bundle nightly (re-validates against RE2; needs the go toolchain)
30 3 * * *  cd /etc/caddy && /usr/bin/python3 get_owasp_rules.py --output /etc/caddy/feeds/crs-pl1.json >> /var/log/caddy/owasp.log 2>&1
```

When the script writes a new `ip_blacklist.txt` or `dns_blacklist.txt` over the file pointed to by the corresponding `*_file` directive, the file watcher fires and the WAF rebuilds the prefix trie / DNS map atomically (see [dynamicupdates.md](dynamicupdates.md)).

## Operational notes

- Always validate the generated `rules.json` with `jq . rules.json > /dev/null` before letting the WAF reload it; an invalid JSON file fails the reload and the previous rules remain in effect.
- Keep generated files in a separate directory (e.g. `/etc/caddy/feeds/`) and reference them from the Caddyfile. Mixing generated and hand-authored rules in the same file invites accidental overwrites.
- For air-gapped environments, run the scripts on a connected host and copy the outputs over.
