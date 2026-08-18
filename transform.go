package caddywaf

import (
	"fmt"
	"strings"
)

// Input transformations for rule matching.
//
// The problem these solve (confirmed empirically, see CHANGELOG v0.4.0): a rule
// regex compares literal bytes, but the application behind the WAF decodes the
// request before acting on it. So "%75nion%20select" in a query string, a form
// body, or the URI never matches a literal "union select" pattern, even though
// the backend will execute it. The WAF has to inspect the input the way the
// backend will consume it.
//
// The matching strategy is ADDITIVE dual-match (see matchTargetValue): a rule is
// tested against the raw value first, then against a transformed copy, and fires
// if EITHER matches. Because the raw value is always tested, no rule that matches
// today can stop matching -- the transformations can only ever add coverage,
// never remove it. That is the whole safety argument for changing this in a
// point release's worth of rules.
//
// Two hard guardrails, both from how ModSecurity/CRS/Coraza do it and both
// load-bearing:
//
//   - Decoding is SINGLE-PASS, never recursive. The application decodes once, so
//     the WAF decodes once. Decoding "%2520" to a space would make the WAF see
//     something the backend never will, manufacturing false positives.
//   - Decoders are LENIENT. A malformed escape ("%", "%zz", a trailing "%a")
//     is left literal, never dropped. Go's url.QueryUnescape errors and would
//     blank the whole value on a single bad byte -- which would itself be a
//     bypass (send one stray "%" and the transformed copy vanishes).

// transformFn is a single, idempotent-enough input transformation.
type transformFn func(string) string

// transformRegistry maps the transformation names a rule may list in its
// optional "transformations" field to their implementations. Names are the
// ModSecurity/CRS names without the SecLang "t:" prefix; the loader also accepts
// the "t:" form and lower-cases before lookup, so "t:urlDecodeUni" and
// "urldecodeuni" both resolve.
var transformRegistry = map[string]transformFn{
	"none":               func(s string) string { return s },
	"lowercase":          strings.ToLower,
	"removenulls":        removeNulls,
	"compresswhitespace": compressWhitespace,
	"urldecode":          func(s string) string { return percentDecodeOnce(s, true) },
	"urldecodeuni":       func(s string) string { return percentDecodeOnce(s, true) }, // %uXXXX handled in a follow-up; plain %XX for now
	"replacecomments":    replaceComments,
	"htmlentitydecode":   htmlEntityDecodeOnce,
}

// defaultRequestChain is applied to the raw request targets (ARGS, URI, URL,
// BODY) when a rule does not specify its own transformations. It is intentionally
// conservative: peel one layer of percent-encoding, drop nulls, fold whitespace.
// Richer decoders (HTML entities, SQL comments, %uXXXX) are available per rule
// via the transformations field but are not global defaults, because applied
// blindly they distort unrelated data.
var defaultRequestChain = []string{"urldecode", "removenulls", "compresswhitespace"}

// percentDecodeOnce decodes %XX sequences exactly once. A "%" not followed by two
// hex digits is emitted literally rather than erroring. When plusToSpace is true
// (query and form-body context) a "+" becomes a space; in path context it must
// stay literal.
func percentDecodeOnce(s string, plusToSpace bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case c == '+' && plusToSpace:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// removeNulls strips NUL bytes, which are used to truncate strings and split
// keywords ("un\x00ion"). Runs after decoding so a decoded %00 is also caught.
func removeNulls(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// compressWhitespace folds any run of ASCII whitespace to a single space,
// defeating tab/newline substitution for the space in payloads.
func compressWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWS := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
			continue
		}
		inWS = false
		b.WriteByte(c)
	}
	return b.String()
}

// replaceComments replaces C-style /* ... */ comments with a single space,
// defeating SQL comment-injection obfuscation such as "un/**/ion".
func replaceComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				b.WriteByte(' ') // unterminated comment: to end
				break
			}
			b.WriteByte(' ')
			i += 2 + end + 2
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// htmlEntityDecodeOnce decodes the small set of HTML entities that matter for
// XSS detection: numeric (&#39; &#x27;) and the common named ones. Single pass.
func htmlEntityDecodeOnce(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	repl := strings.NewReplacer(
		"&lt;", "<", "&gt;", ">", "&quot;", "\"", "&apos;", "'", "&amp;", "&",
		"&#39;", "'", "&#x27;", "'", "&#34;", "\"", "&#x22;", "\"",
		"&#60;", "<", "&#x3c;", "<", "&#62;", ">", "&#x3e;", ">",
	)
	return repl.Replace(s)
}

// rawRequestTargets are the request targets extracted in their still-encoded
// wire form (see request.go): ARGS/URI/URL come from RawQuery/RequestURI/String
// and BODY is the raw body. They get the default transformation chain when a
// rule does not specify its own. PATH and ARGS:name are already decoded by Go
// and are left alone by the default.
var rawRequestTargets = map[string]bool{
	"ARGS": true, "URI": true, "URL": true, "BODY": true,
}

func baseTarget(target string) string {
	t := strings.ToUpper(strings.TrimSpace(target))
	if i := strings.IndexByte(t, ':'); i >= 0 {
		return t[:i]
	}
	return t
}

// resolveChain returns the transformation names to apply to this rule/target.
// An explicit per-rule list wins (including an explicit empty list = no-op);
// otherwise the default chain applies only to the raw request targets.
func resolveChain(rule *Rule, target string) []string {
	if rule != nil && rule.Transformations != nil {
		return *rule.Transformations
	}
	if rawRequestTargets[baseTarget(target)] {
		return defaultRequestChain
	}
	return nil
}

// contextualURLDecode decodes percent-encoding once, choosing the + convention
// from the target: query/body context turns + into space, path context keeps it
// literal, and URI/URL are split on the first '?' so each half is right.
func contextualURLDecode(target, value string) string {
	switch baseTarget(target) {
	case "ARGS", "BODY", "URL_PARAM":
		return percentDecodeOnce(value, true)
	case "PATH":
		return percentDecodeOnce(value, false)
	case "URI", "URL":
		if q := strings.IndexByte(value, '?'); q >= 0 {
			return percentDecodeOnce(value[:q], false) + "?" + percentDecodeOnce(value[q+1:], true)
		}
		return percentDecodeOnce(value, false)
	default:
		return percentDecodeOnce(value, true)
	}
}

// normalizeForTarget applies the resolved transformation chain to value and
// reports whether the result differs from the input. A false second return means
// there is nothing new to match, so the caller can skip the extra regex run.
func normalizeForTarget(rule *Rule, target, value string) (string, bool) {
	chain := resolveChain(rule, target)
	if len(chain) == 0 {
		return value, false
	}
	out := value
	for _, name := range chain {
		key := strings.ToLower(strings.TrimSpace(name))
		key = strings.TrimPrefix(key, "t:")
		if key == "urldecode" || key == "urldecodeuni" {
			out = contextualURLDecode(target, out)
			continue
		}
		if fn, ok := transformRegistry[key]; ok {
			out = fn(out)
		}
		// Unknown names are ignored here; they are rejected at load time.
	}
	return out, out != value
}

// validateTransformations checks a rule's transformation names at load time so a
// typo fails startup rather than silently doing nothing at request time.
func validateTransformations(names []string) error {
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		key = strings.TrimPrefix(key, "t:")
		if key == "urldecode" || key == "urldecodeuni" {
			continue
		}
		if _, ok := transformRegistry[key]; !ok {
			return errUnknownTransform(name)
		}
	}
	return nil
}

func errUnknownTransform(name string) error {
	return fmt.Errorf("unknown transformation %q (known: urlDecode, urlDecodeUni, lowercase, removeNulls, compressWhitespace, replaceComments, htmlEntityDecode, none)", name)
}
