// Package setupsource owns the operator-only test-venue source gate that the
// Runtime forwards to the packaged setup runner. It is deliberately separate
// from every request/wire type: the allowlist can only come from Runtime
// operator configuration, never from a setup operation or any other
// caller-supplied JSON.
//
// The gate mirrors the Sandbox runner contract (WP-60):
//
//   - off by default; absent configuration emits no environment at all;
//   - enabled requires an allowlist of 1..8 exact HTTPS URLs (<= 8 KiB JSON);
//   - every entry is a well-formed public HTTPS URL: ASCII, no whitespace, no
//     userinfo, no fragment, port 443 only, and not localhost/.local/.internal;
//   - duplicates, an empty list, or any malformed entry fail closed before the
//     setup runner is executed.
//
// The Runtime validator is intentionally a strict subset of the runner's: it
// also refuses IP-literal entries, because a test venue addresses its
// cell-local stub by a public DNS name and an IP-literal exception would make
// the trust boundary harder to read. The runner still re-validates everything
// in the cell; the Runtime check exists so a misconfigured venue fails before
// any container execution rather than inside it.
package setupsource

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
)

const (
	// ModeEnv is the setup runner's test-venue switch. The Runtime only ever
	// sets it to ModeEnabled.
	ModeEnv = "WARPMETAL_SETUP_TEST_SOURCE_MODE"
	// AllowlistEnv carries the JSON array of exact exempted artifact URLs.
	AllowlistEnv = "WARPMETAL_SETUP_TEST_SOURCE_ALLOWLIST"
	// ModeEnabled is the only accepted mode value.
	ModeEnabled = "1"
	// MaxAllowlistEntries bounds the list, matching MAX_TEST_SOURCE_ALLOWLIST_ENTRIES.
	MaxAllowlistEntries = 8
	// MaxAllowlistBytes bounds the serialized environment value, matching
	// MAX_TEST_SOURCE_ALLOWLIST_BYTES.
	MaxAllowlistBytes = 8 * 1024
	// maxEntryBytes matches the runner's artifact-source grammar bound.
	maxEntryBytes = 512
)

// Config is the operator-controlled test source gate. It is decoded from the
// root-only Runtime config file; it must never be embedded in a manifest,
// setup request, or any other control-plane payload.
type Config struct {
	// Enabled requests the test-venue gate. When false (or when the whole
	// object is absent) the Runtime emits no gate environment and the
	// production SSRF guard remains fully strict.
	Enabled bool `json:"enabled"`
	// Allowlist is the exact set of artifact URLs exempted from the
	// non-public-address checks by the setup runner. Membership is exact
	// string equality.
	Allowlist []string `json:"allowlist,omitempty"`
}

// Validate fails closed when the gate is requested without a usable
// allowlist. A disabled gate is valid and carries no authority.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if len(c.Allowlist) < 1 || len(c.Allowlist) > MaxAllowlistEntries {
		return fmt.Errorf(
			"setup test source allowlist must contain 1 to %d entries",
			MaxAllowlistEntries,
		)
	}
	encoded, err := json.Marshal(c.Allowlist)
	if err != nil {
		return errors.New("setup test source allowlist is not encodable")
	}
	if len(encoded) > MaxAllowlistBytes {
		return fmt.Errorf(
			"setup test source allowlist exceeds %d bytes",
			MaxAllowlistBytes,
		)
	}
	seen := make(map[string]struct{}, len(c.Allowlist))
	for _, entry := range c.Allowlist {
		if _, duplicate := seen[entry]; duplicate {
			return errors.New("setup test source allowlist contains a duplicate entry")
		}
		if err := validateEntry(entry); err != nil {
			return err
		}
		seen[entry] = struct{}{}
	}
	return nil
}

// Environment returns the exact `NAME=value` environment pairs the setup
// runner must receive, or nil when the gate is off. It validates again so a
// Config constructed outside config.Load can never widen the guard.
func (c *Config) Environment() ([]string, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(c.Allowlist)
	if err != nil {
		return nil, errors.New("setup test source allowlist is not encodable")
	}
	return []string{
		ModeEnv + "=" + ModeEnabled,
		AllowlistEnv + "=" + string(encoded),
	}, nil
}

func validateEntry(value string) error {
	if value == "" || len(value) > maxEntryBytes {
		return errors.New("setup test source allowlist entry is invalid")
	}
	for _, character := range value {
		if character > unicode.MaxASCII || character < 0x20 ||
			character == 0x7f || unicode.IsSpace(character) {
			return errors.New("setup test source allowlist entry is invalid")
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return errors.New("setup test source allowlist entry is invalid")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return errors.New("setup test source allowlist entry is invalid")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("setup test source allowlist entry is not a public host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("setup test source allowlist entry must use a public host name")
	}
	return nil
}
