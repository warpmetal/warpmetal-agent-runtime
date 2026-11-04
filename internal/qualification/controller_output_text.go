package qualification

import (
	"strings"
	"unicode/utf8"
)

// controllerOutputText is a wire-independent byte transform, not a producer or
// authorization consumer. A future frozen native readback adapter must FIRST
// establish completed text parts in native ordinal order. This helper cannot
// establish origin, completeness, ordinals, terminal state or workflow authority.
// It is deliberately not connected to signing, activity or a workflow route.
func controllerOutputText(parts []string) (string, error) {
	const maxBytes = 16 * 1024
	total := 0
	for _, part := range parts {
		if !utf8.ValidString(part) || len(part) > maxBytes-total {
			return "", ErrUntrusted
		}
		total += len(part)
	}
	return strings.Join(parts, ""), nil
}
