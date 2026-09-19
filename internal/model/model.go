package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	MinTemporarySeconds     = 900
	MaxTemporarySeconds     = 86400
	DefaultTemporarySeconds = 86400
	MaxSetupArtifactBytes   = 2_147_483_648
)

var (
	namePattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	idPattern           = regexp.MustCompile(`^(?:sbx|grant)_[A-Za-z0-9_-]{8,60}$`)
	setupIDPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	imagePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
	setupDigestPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	npmPackagePattern   = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]{0,62}/)?[a-z0-9][a-z0-9._-]{0,62}$`)
	npmBinPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	relativePathPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,256}$`)
	semverPattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	validDesired        = map[string]bool{"running": true, "stopped": true, "deleted": true}
)

type Resources struct {
	CPUMillicores    int `json:"cpuMillicores"`
	MemoryMiB        int `json:"memoryMiB"`
	WorkspaceDiskGiB int `json:"workspaceDiskGiB"`
	PIDs             int `json:"pids"`
}

func (r Resources) Add(other Resources) Resources {
	return Resources{
		CPUMillicores:    r.CPUMillicores + other.CPUMillicores,
		MemoryMiB:        r.MemoryMiB + other.MemoryMiB,
		WorkspaceDiskGiB: r.WorkspaceDiskGiB + other.WorkspaceDiskGiB,
		PIDs:             r.PIDs + other.PIDs,
	}
}

func (r Resources) Fits(capacity Resources) bool {
	return r.CPUMillicores <= capacity.CPUMillicores &&
		r.MemoryMiB <= capacity.MemoryMiB &&
		r.WorkspaceDiskGiB <= capacity.WorkspaceDiskGiB
}

type Sandbox struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Size             string     `json:"size"`
	Resources        Resources  `json:"resources"`
	ImageDigest      string     `json:"imageDigest,omitempty"`
	Lifetime         string     `json:"lifetime"`
	ExpiresInSeconds *int       `json:"expiresInSeconds"`
	StartedAt        *time.Time `json:"startedAt"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	DesiredState     string     `json:"desiredState"`
	Generation       int64      `json:"generation"`
}

// Keep the retired cliTools member inert during rolling upgrades without
// permitting arbitrary new sandbox controls through the closed manifest API.
func (sandbox *Sandbox) UnmarshalJSON(payload []byte) error {
	type wireSandbox Sandbox
	var decoded struct {
		wireSandbox
		LegacyTools json.RawMessage `json:"cliTools"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*sandbox = Sandbox(decoded.wireSandbox)
	return nil
}

type AccessGrant struct {
	ID             string `json:"id"`
	SandboxID      string `json:"sandboxId"`
	SSHPublicKey   string `json:"sshPublicKey"`
	SSHFingerprint string `json:"sshFingerprint"`
	DesiredState   string `json:"desiredState"`
}

type SetupArtifact struct {
	ID             string `json:"id"`
	Source         string `json:"source"`
	SHA256         string `json:"sha256"`
	Format         string `json:"format"`
	SizeBytes      int64  `json:"sizeBytes"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	InstallAs      string `json:"installAs"`
}

type SetupMaterializer struct {
	Kind      string                `json:"kind"`
	Artifacts []SetupArtifact       `json:"artifacts,omitempty"`
	Bins      []string              `json:"bins,omitempty"`
	Launchers []SetupLauncher       `json:"launchers,omitempty"`
	Artifact  *SetupArchiveArtifact `json:"artifact,omitempty"`
	Bin       *SetupArchiveBin      `json:"bin,omitempty"`
}

type SetupLauncher struct {
	Bin         string            `json:"bin"`
	Kind        string            `json:"kind"`
	ArtifactID  string            `json:"artifactId"`
	Entrypoint  string            `json:"entrypoint"`
	Environment map[string]string `json:"environment"`
}

type SetupArchiveArtifact struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"sizeBytes"`
}

type SetupArchiveBin struct {
	Name   string `json:"name"`
	Member string `json:"member"`
}

func (materializer SetupMaterializer) MarshalJSON() ([]byte, error) {
	switch materializer.Kind {
	case "npm-package-set":
		return json.Marshal(struct {
			Kind      string          `json:"kind"`
			Artifacts []SetupArtifact `json:"artifacts"`
			Bins      []string        `json:"bins"`
			Launchers []SetupLauncher `json:"launchers,omitempty"`
		}{materializer.Kind, materializer.Artifacts, materializer.Bins, materializer.Launchers})
	case "archive-binary":
		return json.Marshal(struct {
			Kind     string                `json:"kind"`
			Artifact *SetupArchiveArtifact `json:"artifact"`
			Bin      *SetupArchiveBin      `json:"bin"`
		}{materializer.Kind, materializer.Artifact, materializer.Bin})
	default:
		type raw SetupMaterializer
		return json.Marshal(raw(materializer))
	}
}

type SetupOperation struct {
	ID                string            `json:"id"`
	SchemaVersion     int               `json:"schemaVersion"`
	SandboxID         string            `json:"sandboxId"`
	SandboxGeneration int64             `json:"sandboxGeneration"`
	ProfileID         string            `json:"profileId"`
	ProfileRevision   int64             `json:"profileRevision"`
	ProfileDigest     string            `json:"profileDigest"`
	Materializer      SetupMaterializer `json:"materializer"`
}

type Manifest struct {
	ServerID        string           `json:"serverId"`
	DesiredRevision int64            `json:"desiredRevision"`
	ImageDigest     string           `json:"imageDigest"`
	Capacity        Resources        `json:"capacity"`
	Sandboxes       []Sandbox        `json:"sandboxes"`
	AccessGrants    []AccessGrant    `json:"accessGrants"`
	SetupOperations []SetupOperation `json:"setupOperations,omitempty"`
}

type ItemError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

type SandboxReport struct {
	ID                 string     `json:"id"`
	ObservedState      string     `json:"observedState"`
	ObservedGeneration int64      `json:"observedGeneration"`
	ImageDigest        string     `json:"imageDigest,omitempty"`
	StartedAt          *time.Time `json:"startedAt,omitempty"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
	LastError          *ItemError `json:"lastError,omitempty"`
}

type GrantReport struct {
	ID            string     `json:"id"`
	ObservedState string     `json:"observedState"`
	LastError     *ItemError `json:"lastError,omitempty"`
}

type SetupOperationReport struct {
	ID                string     `json:"id"`
	SandboxID         string     `json:"sandboxId"`
	SandboxGeneration int64      `json:"sandboxGeneration"`
	ProfileID         string     `json:"profileId"`
	ProfileRevision   int64      `json:"profileRevision"`
	ProfileDigest     string     `json:"profileDigest"`
	Status            string     `json:"status"`
	ReceiptDigest     string     `json:"receiptDigest,omitempty"`
	LastError         *ItemError `json:"lastError,omitempty"`
}

type Report struct {
	ServerID          string                 `json:"serverId"`
	AppliedRevision   int64                  `json:"appliedRevision"`
	SupervisorVersion string                 `json:"supervisorVersion"`
	ImageDigest       string                 `json:"imageDigest,omitempty"`
	HostKeys          []HostKey              `json:"hostKeys,omitempty"`
	LastError         *ItemError             `json:"lastError,omitempty"`
	Sandboxes         []SandboxReport        `json:"sandboxes"`
	AccessGrants      []GrantReport          `json:"accessGrants"`
	SetupOperations   []SetupOperationReport `json:"setupOperations"`
}

type HostKey struct {
	Algorithm   string `json:"algorithm,omitempty"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func ValidateManifest(manifest Manifest, expectedServer string, lastRevision int64) error {
	if manifest.ServerID != expectedServer {
		return errors.New("manifest server identity differs from local registration")
	}
	if manifest.DesiredRevision < lastRevision {
		return errors.New("manifest revision moved backwards")
	}
	if manifest.DesiredRevision < 1 || len(manifest.Sandboxes) > 32 || len(manifest.AccessGrants) > 64 {
		return errors.New("manifest limits are invalid")
	}
	if !imagePattern.MatchString(manifest.ImageDigest) {
		return errors.New("immutable sandbox image digest is required")
	}
	seenNames := map[string]bool{}
	seenIDs := map[string]bool{}
	sandboxStates := map[string]string{}
	sandboxGenerations := map[string]int64{}
	allocated := Resources{}
	for _, sandbox := range manifest.Sandboxes {
		if !idPattern.MatchString(sandbox.ID) || !namePattern.MatchString(sandbox.Name) {
			return fmt.Errorf("invalid sandbox identity %q", sandbox.ID)
		}
		if seenIDs[sandbox.ID] || seenNames[sandbox.Name] {
			return errors.New("duplicate sandbox identity")
		}
		seenIDs[sandbox.ID] = true
		seenNames[sandbox.Name] = true
		sandboxStates[sandbox.ID] = sandbox.DesiredState
		sandboxGenerations[sandbox.ID] = sandbox.Generation
		if !validDesired[sandbox.DesiredState] || sandbox.Generation < 1 {
			return fmt.Errorf("invalid desired state for %s", sandbox.ID)
		}
		if sandbox.ImageDigest != "" && !imagePattern.MatchString(sandbox.ImageDigest) {
			return fmt.Errorf("invalid image digest for %s", sandbox.ID)
		}
		if sandbox.Resources.CPUMillicores < 1 || sandbox.Resources.MemoryMiB < 1 ||
			sandbox.Resources.WorkspaceDiskGiB < 1 || sandbox.Resources.PIDs < 1 {
			return fmt.Errorf("invalid resource snapshot for %s", sandbox.ID)
		}
		if sandbox.Lifetime == "persistent" {
			if sandbox.ExpiresInSeconds != nil || sandbox.ExpiresAt != nil {
				return fmt.Errorf("persistent sandbox %s has expiration", sandbox.ID)
			}
		} else if sandbox.Lifetime == "temporary" {
			if sandbox.ExpiresInSeconds == nil || *sandbox.ExpiresInSeconds < MinTemporarySeconds ||
				*sandbox.ExpiresInSeconds > MaxTemporarySeconds {
				return fmt.Errorf("temporary sandbox %s has invalid expiration", sandbox.ID)
			}
		} else {
			return fmt.Errorf("invalid lifetime for %s", sandbox.ID)
		}
		if sandbox.DesiredState != "deleted" {
			allocated.WorkspaceDiskGiB += sandbox.Resources.WorkspaceDiskGiB
			if sandbox.DesiredState == "running" {
				allocated.CPUMillicores += sandbox.Resources.CPUMillicores
				allocated.MemoryMiB += sandbox.Resources.MemoryMiB
			}
		}
	}
	if !allocated.Fits(manifest.Capacity) {
		return errors.New("manifest exceeds purchased runtime capacity")
	}
	if len(manifest.SetupOperations) > 32 {
		return errors.New("manifest exceeds setup operation limit")
	}
	seenSetupIDs := map[string]bool{}
	for _, operation := range manifest.SetupOperations {
		if !setupIDPattern.MatchString(operation.ID) || seenSetupIDs[operation.ID] {
			return errors.New("invalid or duplicate setup operation identity")
		}
		seenSetupIDs[operation.ID] = true
		generation, exists := sandboxGenerations[operation.SandboxID]
		if !exists || generation != operation.SandboxGeneration {
			return fmt.Errorf("setup operation %s has an invalid sandbox generation", operation.ID)
		}
		if operation.SchemaVersion != 1 ||
			!setupIDPattern.MatchString(operation.ProfileID) ||
			operation.ProfileRevision < 1 ||
			!setupDigestPattern.MatchString(operation.ProfileDigest) {
			return fmt.Errorf("setup operation %s has an invalid immutable tuple", operation.ID)
		}
		var materializerErr error
		switch operation.Materializer.Kind {
		case "npm-package-set":
			materializerErr = validateNPMMaterializer(operation.Materializer)
		case "archive-binary":
			materializerErr = validateArchiveMaterializer(operation.Materializer)
		default:
			materializerErr = errors.New("unsupported materializer")
		}
		if materializerErr != nil {
			return fmt.Errorf("setup operation %s has an invalid materializer: %w", operation.ID, materializerErr)
		}
	}
	seenGrants := map[string]bool{}
	seenKeys := map[string]bool{}
	grantsPerSandbox := map[string]int{}
	for _, grant := range manifest.AccessGrants {
		if !idPattern.MatchString(grant.ID) || !seenIDs[grant.SandboxID] {
			return fmt.Errorf("invalid access grant %q", grant.ID)
		}
		if seenGrants[grant.ID] || (grant.DesiredState == "active" && seenKeys[grant.SSHFingerprint]) {
			return errors.New("duplicate access grant or key mapping")
		}
		if grant.DesiredState != "active" && grant.DesiredState != "revoked" {
			return fmt.Errorf("invalid grant state for %s", grant.ID)
		}
		if grant.DesiredState == "active" && sandboxStates[grant.SandboxID] == "deleted" {
			return fmt.Errorf("active grant targets deleted sandbox %s", grant.SandboxID)
		}
		seenGrants[grant.ID] = true
		if grant.DesiredState == "active" {
			seenKeys[grant.SSHFingerprint] = true
			grantsPerSandbox[grant.SandboxID]++
			if grantsPerSandbox[grant.SandboxID] > 8 {
				return fmt.Errorf("sandbox %s exceeds grant limit", grant.SandboxID)
			}
		}
	}
	return nil
}

func validateNPMMaterializer(materializer SetupMaterializer) error {
	if materializer.Artifact != nil || materializer.Bin != nil ||
		len(materializer.Artifacts) < 1 || len(materializer.Artifacts) > 8 ||
		len(materializer.Bins) > 8 || len(materializer.Launchers) > 8 ||
		(len(materializer.Bins) == 0 && len(materializer.Launchers) == 0) {
		return errors.New("invalid npm materializer shape")
	}
	seenArtifacts := map[string]bool{}
	seenAliases := map[string]bool{}
	var aggregateSize int64
	for _, artifact := range materializer.Artifacts {
		if !setupIDPattern.MatchString(artifact.ID) || seenArtifacts[artifact.ID] ||
			!setupDigestPattern.MatchString(artifact.SHA256) ||
			artifact.Format != "npm-tgz" || artifact.SizeBytes < 1 ||
			artifact.SizeBytes > MaxSetupArtifactBytes ||
			!npmPackagePattern.MatchString(artifact.PackageName) ||
			!semverPattern.MatchString(artifact.PackageVersion) ||
			!npmPackagePattern.MatchString(artifact.InstallAs) ||
			seenAliases[artifact.InstallAs] {
			return errors.New("invalid npm artifact")
		}
		seenArtifacts[artifact.ID] = true
		seenAliases[artifact.InstallAs] = true
		aggregateSize += artifact.SizeBytes
		if aggregateSize > MaxSetupArtifactBytes {
			return errors.New("artifact size limit exceeded")
		}
		if err := validateSetupArtifactSource(artifact.Source); err != nil {
			return errors.New("invalid artifact source")
		}
	}
	seenBins := map[string]bool{}
	for _, bin := range materializer.Bins {
		if !npmBinPattern.MatchString(bin) || seenBins[bin] {
			return errors.New("invalid npm bin")
		}
		seenBins[bin] = true
	}
	for _, launcher := range materializer.Launchers {
		if !npmBinPattern.MatchString(launcher.Bin) || seenBins[launcher.Bin] ||
			launcher.Kind != "node-module" || !seenArtifacts[launcher.ArtifactID] ||
			!safeRelativePath(launcher.Entrypoint) ||
			len(launcher.Environment) != 1 || launcher.Environment["DISABLE_UPDATES"] != "1" {
			return errors.New("invalid npm launcher")
		}
		seenBins[launcher.Bin] = true
	}
	return nil
}

func validateArchiveMaterializer(materializer SetupMaterializer) error {
	if len(materializer.Artifacts) != 0 || len(materializer.Bins) != 0 ||
		len(materializer.Launchers) != 0 || materializer.Artifact == nil || materializer.Bin == nil {
		return errors.New("invalid archive materializer shape")
	}
	artifact := materializer.Artifact
	if !setupIDPattern.MatchString(artifact.ID) ||
		!setupDigestPattern.MatchString(artifact.SHA256) || artifact.Format != "tar-gz" ||
		artifact.SizeBytes < 1 || artifact.SizeBytes > MaxSetupArtifactBytes ||
		validateSetupArtifactSource(artifact.Source) != nil {
		return errors.New("invalid archive artifact")
	}
	if !npmBinPattern.MatchString(materializer.Bin.Name) ||
		!npmBinPattern.MatchString(materializer.Bin.Member) ||
		strings.Contains(materializer.Bin.Member, "/") {
		return errors.New("invalid archive bin")
	}
	return nil
}

func safeRelativePath(value string) bool {
	if !relativePathPattern.MatchString(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validateSetupArtifactSource(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || len(value) > len("https://")+500 || parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" || parsed.User != nil ||
		strings.ContainsRune(value, '#') {
		return errors.New("artifact source must be an absolute HTTPS URL")
	}
	for _, character := range value[len("https://"):] {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._~:/?#[\\]@!$&'()*+,;=%-", character) {
			continue
		}
		return errors.New("artifact source contains an unsupported character")
	}
	return nil
}
