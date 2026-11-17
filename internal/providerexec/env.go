package providerexec

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// defaultExecutorPath is the fixed PATH used when the Runtime's own PATH is
	// unusable, so a reviewed executor still finds standard tools.
	defaultExecutorPath = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	// maxEnvValueBytes bounds each inherited environment value.
	maxEnvValueBytes = 4096
)

// minimalEnv builds the child environment from a fixed allowlist instead of
// inheriting the Runtime's environment. Ambient KEY/PASSWORD/SECRET/TOKEN/DSH_*
// variables and every other unrelated variable (including provider secrets the
// Runtime may hold) are therefore invisible to the external executor.
//
// PATH is kept because a reviewed executor may invoke standard tools; it is
// reduced to absolute, control-free entries. HOME and LANG are kept because they
// are not provider secrets and many tools require them for ordinary operation.
func minimalEnv() []string {
	environment := make([]string, 0, 3)
	path := sanitizedPath(os.Getenv("PATH"))
	if path == "" {
		path = defaultExecutorPath
	}
	environment = append(environment, "PATH="+path)
	if home := safeEnvValue(os.Getenv("HOME")); home != "" && filepath.IsAbs(home) {
		environment = append(environment, "HOME="+home)
	}
	if lang := safeEnvValue(os.Getenv("LANG")); lang != "" {
		environment = append(environment, "LANG="+lang)
	}
	return environment
}

// sanitizedPath reduces a PATH value to its absolute, control-free,
// non-expandable entries. An empty result means "use the default".
func sanitizedPath(value string) string {
	if value == "" {
		return ""
	}
	entries := strings.Split(value, ":")
	kept := make([]string, 0, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		if entry == "" || !filepath.IsAbs(entry) || strings.Contains(entry, "..") {
			continue
		}
		if !utf8.ValidString(entry) || strings.ContainsRune(entry, 0) {
			continue
		}
		if strings.IndexFunc(entry, unicode.IsControl) >= 0 {
			continue
		}
		if totalBytes+len(entry) > maxEnvValueBytes {
			break
		}
		totalBytes += len(entry)
		kept = append(kept, entry)
	}
	return strings.Join(kept, ":")
}

// safeEnvValue bounds and sanitizes one allowlisted environment value.
func safeEnvValue(value string) string {
	if value == "" || len(value) > maxEnvValueBytes {
		return ""
	}
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return ""
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return ""
	}
	return value
}
