package providergateway

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// redactedMarker replaces any occurrence of a credential secret value.
	redactedMarker = "[redacted]"
	// truncationMarker is appended when bounded text is cut.
	truncationMarker = "\u2026[truncated]"
)

// redact replaces every occurrence of a known credential secret value with
// redactedMarker. It is the last line of defence for text the gateway surfaces
// or logs: even an Executor that somehow obtained a secret value cannot leak it
// through a tool result or an error message. g.secrets is immutable while
// connections are served, and is zeroized only after every handler has stopped.
func (g *Gateway) redact(text string) string {
	if len(text) == 0 || len(g.secrets) == 0 {
		return text
	}
	data := []byte(text)
	for _, secret := range g.secrets {
		data = bytes.ReplaceAll(data, secret, []byte(redactedMarker))
	}
	return string(data)
}

// sanitizeText makes text safe to embed in JSON-RPC content: invalid UTF-8 is
// replaced and NUL bytes are removed. JSON encoding escapes control characters,
// so newlines in tool output are preserved for the model.
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

// logSafe renders arbitrary error text on a single bounded log line. Control
// characters are removed or folded to spaces so provider text cannot forge log
// lines; the text must already be redacted.
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
	return truncateText(strings.TrimSpace(text), maxLogErrorBytes)
}
