package model

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	MinTemporarySeconds     = 900
	MaxTemporarySeconds     = 86400
	DefaultTemporarySeconds = 86400
)

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	idPattern    = regexp.MustCompile(`^(?:sbx|grant)_[A-Za-z0-9_-]{8,60}$`)
	imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
	validDesired = map[string]bool{"running": true, "stopped": true, "deleted": true}
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
	Lifetime         string     `json:"lifetime"`
	ExpiresInSeconds *int       `json:"expiresInSeconds"`
	StartedAt        *time.Time `json:"startedAt"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	DesiredState     string     `json:"desiredState"`
	Generation       int64      `json:"generation"`
}

type AccessGrant struct {
	ID             string `json:"id"`
	SandboxID      string `json:"sandboxId"`
	SSHPublicKey   string `json:"sshPublicKey"`
	SSHFingerprint string `json:"sshFingerprint"`
	DesiredState   string `json:"desiredState"`
}

type Manifest struct {
	ServerID        string        `json:"serverId"`
	DesiredRevision int64         `json:"desiredRevision"`
	ImageDigest     string        `json:"imageDigest"`
	Capacity        Resources     `json:"capacity"`
	Sandboxes       []Sandbox     `json:"sandboxes"`
	AccessGrants    []AccessGrant `json:"accessGrants"`
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

type Report struct {
	ServerID          string          `json:"serverId"`
	AppliedRevision   int64           `json:"appliedRevision"`
	SupervisorVersion string          `json:"supervisorVersion"`
	ImageDigest       string          `json:"imageDigest,omitempty"`
	HostKeys          []HostKey       `json:"hostKeys,omitempty"`
	LastError         *ItemError      `json:"lastError,omitempty"`
	Sandboxes         []SandboxReport `json:"sandboxes"`
	AccessGrants      []GrantReport   `json:"accessGrants"`
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
		if !validDesired[sandbox.DesiredState] || sandbox.Generation < 1 {
			return fmt.Errorf("invalid desired state for %s", sandbox.ID)
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
