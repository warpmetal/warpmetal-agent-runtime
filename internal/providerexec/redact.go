package providerexec

import (
	"bytes"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// redactedMarker replaces any occurrence of a known credential field value.
	redactedMarker = "[redacted]"
	// truncationMarker is appended when bounded text is cut.
	truncationMarker = "\u2026[truncated]"
)

// redactor removes every occurrence of the known credential field values from
// text that leaves this process (tool result text, error text, log lines).
type redactor struct {
	secrets [][]byte
}

// newRedactor builds a redactor from one per-call credential snapshot. Values
// are copied into byte slices so release can zero them. A nil or empty map
// yields a redactor that never matches.
func newRedactor(fields map[string]string) *redactor {
	secrets := make([][]byte, 0, len(fields))
	for _, value := range fields {
		if value == "" {
			continue
		}
		secrets = append(secrets, []byte(value))
	}
	// Replace longer values first: with a shorter secret that is a substring of
	// a longer one, replacing the short one first could destroy the shape of the
	// longer match without removing all of it.
	sort.Slice(secrets, func(left, right int) bool {
		return len(secrets[left]) > len(secrets[right])
	})
	return &redactor{secrets: secrets}
}

// redact replaces every occurrence of a known credential value.
func (r *redactor) redact(text string) string {
	if r == nil || len(text) == 0 || len(r.secrets) == 0 {
		return text
	}
	data := []byte(text)
	for _, secret := range r.secrets {
		data = bytes.ReplaceAll(data, secret, []byte(redactedMarker))
	}
	return string(data)
}

// release zeroizes and drops the transient secret copies. It is best-effort:
// Go strings are immutable, so copies made while building the request cannot be
// zeroed, but no reference survives the call.
func (r *redactor) release() {
	if r == nil {
		return
	}
	for index := range r.secrets {
		zeroBytes(r.secrets[index])
	}
	r.secrets = nil
}

// sanitizeText makes arbitrary executor text safe to embed in a tool result or
// error: invalid UTF-8 is replaced and NUL bytes are removed.
func sanitizeText(text string) string {
	if text == "" {
		return text
	}
	text = strings.ToValidUTF8(text, "\uFFFD")
	if strings.IndexByte(text, 0) < 0 {
		return text
	}
	return strings.ReplaceAll(text, "\x00", "")
}

// truncateText bounds text to limit bytes without splitting a UTF-8 rune and
// appends truncationMarker when anything was dropped. limit must be positive.
func truncateText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + truncationMarker
}

// logSafe renders arbitrary redacted text on a single bounded log line: control
// characters are folded or removed so provider text cannot forge log lines, and
// the result is truncated.
func logSafe(text string) string {
	text = sanitizeText(text)
	text = strings.Map(func(character rune) rune {
		switch {
		case character == '\n' || character == '\r' || character == '\t':
			return ' '
		case unicode.IsControl(character):
			return -1
		default:
			return character
		}
	}, text)
	return truncateText(strings.TrimSpace(text), maxErrorTextBytes)
}

// zeroBytes overwrites a byte slice with zeroes.
func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
