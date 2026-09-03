package caddywaf

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/phemmer/go-iptrie"
	"go.uber.org/zap"
)

// PrivateRangesToken is the shorthand accepted by the whitelist_ip directive.
// It expands to privateRanges below, matching the set Caddy uses for its own
// private_ranges placeholder, so an operator does not have to remember two
// different definitions of "private".
const PrivateRangesToken = "private_ranges"

// privateRanges mirrors Caddy's private_ranges. Deliberately identical rather
// than "improved": a WAF and the server in front of it disagreeing about which
// addresses are private is the kind of subtle mismatch that produces a bypass.
var privateRanges = []string{
	"192.168.0.0/16",
	"172.16.0.0/12",
	"10.0.0.0/8",
	"127.0.0.1/8",
	"fd00::/8",
	"::1",
}

// buildIPWhitelist compiles the configured entries into a prefix trie.
//
// Entries may be a bare IP, a CIDR range, or PrivateRangesToken. An
// unparseable entry is an error rather than a warning: a whitelist that
// silently drops an entry fails in the dangerous direction for the operator
// (their address is not exempt) and there is no reason to guess.
func buildIPWhitelist(entries []string) (*iptrie.Trie, []string, error) {
	return buildIPTrie(entries, "whitelist_ip")
}

// buildIPTrie compiles IP/CIDR entries (and the private_ranges token) into a
// prefix trie, returning the expanded entry list. An unparseable entry is an
// error, not a warning: silently dropping one fails in the dangerous direction.
// directive names the source for the error message.
func buildIPTrie(entries []string, directive string) (*iptrie.Trie, []string, error) {
	trie := iptrie.NewTrie()
	var expanded []string

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, PrivateRangesToken) {
			expanded = append(expanded, privateRanges...)
			continue
		}
		expanded = append(expanded, entry)
	}

	for _, entry := range expanded {
		cidr := entry
		if !strings.Contains(cidr, "/") {
			cidr = appendCIDR(cidr)
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid %s entry %q: %w", directive, entry, err)
		}
		trie.Insert(prefix, nil)
	}

	return trie, expanded, nil
}

// isIPWhitelisted reports whether addr is exempt from the IP-reputation checks.
//
// It takes ONLY the peer address, never X-Forwarded-For, and that asymmetry
// with the blacklist is deliberate. For blocking, consulting extra addresses
// can only ever block more, so the forwarded chain is fair game. For allowing,
// the opposite holds: honouring a client-supplied header would let anyone send
// "X-Forwarded-For: 10.0.0.1" and exempt themselves from the blacklist, the
// country filter and the ASN filter in one move. The peer address is the only
// value a client cannot forge, so it is the only one trusted here.
func (m *Middleware) isIPWhitelisted(remoteAddr string) bool {
	m.mu.RLock()
	trie := m.ipWhitelist
	m.mu.RUnlock()

	if trie == nil {
		return false
	}

	ip := extractIP(remoteAddr)
	parsed, err := netip.ParseAddr(ip)
	if err != nil {
		m.logger.Debug("Failed to parse peer address for whitelist check",
			zap.String("ip", ip), zap.Error(err))
		return false
	}

	return trie.Contains(parsed)
}

// loadIPWhitelistFile reads IP/CIDR entries from path and inserts them into
// trie, returning the number of valid entries. Blank lines and # comments are
// ignored. A malformed line is skipped with a warning rather than failing the
// whole load: a whitelist fed from a maintained external list (a provider's
// published ranges) should tolerate the odd bad line instead of dropping every
// exemption. Mirrors the IP blacklist file loader.
func (m *Middleware) loadIPWhitelistFile(path string, trie *iptrie.Trie) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("failed to open whitelist file %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	valid := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidr := line
		if !strings.Contains(cidr, "/") {
			cidr = appendCIDR(cidr)
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			m.logger.Warn("Skipping invalid entry in whitelist file",
				zap.String("file", path), zap.String("entry", line), zap.Error(err))
			continue
		}
		trie.Insert(prefix, nil)
		valid++
	}
	if err := scanner.Err(); err != nil {
		return valid, fmt.Errorf("error reading whitelist file %q: %w", path, err)
	}
	return valid, nil
}

// rebuildIPWhitelist builds the whitelist trie from the inline whitelist_ip
// entries and, if configured, the whitelist_file, then swaps it in under the
// lock. It is used at Provision and on hot reload. Inline entries are validated
// strictly (a typo fails startup); file entries are lenient (bad lines skipped),
// matching the blacklist inline-vs-file split.
func (m *Middleware) rebuildIPWhitelist() error {
	trie, expanded, err := buildIPWhitelist(m.IPWhitelist)
	if err != nil {
		return err
	}

	fileEntries := 0
	if m.IPWhitelistFile != "" {
		if _, statErr := os.Stat(m.IPWhitelistFile); os.IsNotExist(statErr) {
			m.logger.Warn("Skipping whitelist file load, file does not exist",
				zap.String("file", m.IPWhitelistFile))
		} else {
			n, loadErr := m.loadIPWhitelistFile(m.IPWhitelistFile, trie)
			if loadErr != nil {
				return loadErr
			}
			fileEntries = n
		}
	}

	m.mu.Lock()
	m.ipWhitelist = trie
	m.mu.Unlock()

	m.logger.Info("IP whitelist loaded",
		zap.Int("inline_entries", len(expanded)),
		zap.Int("file_entries", fileEntries),
		zap.String("file", m.IPWhitelistFile))
	return nil
}
