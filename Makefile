# Canonical local build — the SAME shared release command as
# .github/workflows/release.yml (build job). A manual `go build` that omits
# `-X main.version` produces `version=dev`, which the backend rejects: the cell
# capability gate allowlists exact Runtime releases, and a `dev` report makes
# the backend omit `cell` from the manifest, so the SA9 witness is never
# observed and product cell admission fails `cell_lifecycle_not_ready`.
# Always build through this target (or pass `VERSION=<admitted release>`) so a
# candidate is never misregistered as `dev` or as a superseded release.
VERSION ?= 0.1.52
GOOS ?= linux
GOARCH ?= amd64
GOFLAGS := -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build vet test version

# Build the cross-compiled daemon and fail if the release stamp is missing
# (an unstamped `dev` binary is the exact WP-52 cell-admission defect).
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o dist/warpmetald ./cmd/warpmetald
	@grep -a -F -q '$(VERSION)' dist/warpmetald || { \
		printf 'error: dist/warpmetald is not stamped with version %s\n' '$(VERSION)' >&2; \
		exit 1; \
	}
	@printf 'built dist/warpmetald version=%s (%s/%s)\n' '$(VERSION)' '$(GOOS)' '$(GOARCH)'

# Report the release stamp the canonical target would use.
version:
	@printf '%s\n' '$(VERSION)'

vet:
	go vet ./...

test:
	go test ./...
