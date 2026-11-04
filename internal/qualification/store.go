// Package qualification owns the disabled-by-default, public-only canary store.
// It is not a model catalog, grant issuer, or credential transport.
package qualification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"golang.org/x/sys/unix"
)

var ErrUntrusted = errors.New("qualification refused")
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)
var hash = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Limits struct {
	Preparations  int `json:"preparations"`
	Requests      int `json:"requests"`
	OutputTokens  int `json:"outputTokens"`
	RequestBytes  int `json:"requestBytes"`
	ResponseBytes int `json:"responseBytes"`
	Retries       int `json:"retries"`
}

var Ceilings = Limits{2, 2, 1000, 32768, 262144, 0}

type Bootstrap struct {
	ProviderPolicyDigest    string                         `json:"providerPolicyDigest,omitempty"`
	AccountingVersion       int                            `json:"accountingVersion,omitempty"`
	AuthorityDigest         string                         `json:"authorityDigest,omitempty"`
	SourceBootstrap         *QualificationPublication      `json:"sourceBootstrap,omitempty"`
	Producer                *QualificationProducerIdentity `json:"producer,omitempty"`
	ProducerPublicKeyBase64 string                         `json:"producerPublicKeyBase64,omitempty"`
	FormatVersion           int                            `json:"formatVersion"`
	CampaignID              string                         `json:"campaignId"`
	SandboxID               string                         `json:"sandboxId"`
	SandboxGeneration       int64                          `json:"sandboxGeneration"`
	ImageDigest             string                         `json:"imageDigest"`
	Instance                string                         `json:"instance"`
	ProfileID               string                         `json:"profileId"`
	ProfileDigest           string                         `json:"profileDigest"`
	PluginSHA256            string                         `json:"pluginSha256"`
	CASHA256                string                         `json:"caSha256"`
	Origin                  string                         `json:"origin"`
	ExpiresAt               string                         `json:"expiresAt"`
	Ceilings                Limits                         `json:"ceilings"`
	Mode                    string                         `json:"mode,omitempty"`
	Case                    *RealCase                      `json:"case,omitempty"`
}
type Preparation struct {
	PreparationID string `json:"preparationId"`
	SessionID     string `json:"sessionId"`
	InputID       string `json:"inputId"`
	Workspace     string `json:"workspace"`
}
type Policy struct {
	ProviderPolicyDigest   string                    `json:"providerPolicyDigest,omitempty"`
	AccountingVersion      int                       `json:"accountingVersion,omitempty"`
	AuthorizationBinding   string                    `json:"authorizationBinding,omitempty"`
	SourceBootstrapDigest  string                    `json:"sourceBootstrapDigest,omitempty"`
	SidecarBootstrapDigest string                    `json:"sidecarBootstrapDigest,omitempty"`
	SourcePolicy           *QualificationPublication `json:"sourcePolicy,omitempty"`
	FormatVersion          int                       `json:"formatVersion"`
	CampaignID             string                    `json:"campaignId"`
	SandboxID              string                    `json:"sandboxId"`
	Instance               string                    `json:"instance"`
	ProfileID              string                    `json:"profileId"`
	ProfileDigest          string                    `json:"profileDigest"`
	ProviderID             string                    `json:"providerId"`
	AuthMode               string                    `json:"authMode"`
	ModelID                string                    `json:"modelId"`
	Origin                 string                    `json:"origin"`
	AuthorizationSHA256    string                    `json:"authorizationSha256,omitempty"`
	ExpiresAt              string                    `json:"expiresAt"`
	Preparations           []Preparation             `json:"preparations"`
	PluginSHA256           string                    `json:"pluginSha256"`
	CASHA256               string                    `json:"caSha256"`
	Ceilings               Limits                    `json:"ceilings"`
	PreparedTupleDigest    string                    `json:"preparedTupleDigest"`
	Mode                   string                    `json:"mode,omitempty"`
	Run                    *RealRun                  `json:"run,omitempty"`
}
type Descriptor struct {
	FormatVersion       int    `json:"formatVersion"`
	PreparationID       string `json:"preparationId"`
	PreparedTupleDigest string `json:"preparedTupleDigest"`
	PolicyDigest        string `json:"policyDigest"`
}

// Each revocation is signed and content-addressed; publication can only deny.
type Revocation struct {
	FormatVersion int    `json:"formatVersion"`
	CampaignID    string `json:"campaignId"`
	SandboxID     string `json:"sandboxId"`
	PolicyDigest  string `json:"policyDigest"`
}
type Store struct {
	Root      string
	MappedUID uint32
	// Independently enrolled host configuration, never sidecar-supplied identity.
	ProducerConfig                          *ProducerConfig
	ProducerServerID, ProducerNodeTokenHash string
	sourceProducerIdentity                  *QualificationProducerIdentity
	// SOURCE boundary only: an unexported independent ancestor-owner supplier.
	// Production constructors cannot select it via config/argv/env/wire. Mode,
	// no-follow, regular file/link/inode and immutable payload checks stay real.
	ancestorUID *uint32
}

func (s Store) Paths(id string) (string, string, error) {
	if !regexp.MustCompile(`^sbx_[A-Za-z0-9_-]+$`).MatchString(id) || len(id) > 160 || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root || s.Root == "/" || strings.ContainsAny(s.Root, ":,\n") {
		return "", "", ErrUntrusted
	}
	return filepath.Join(s.Root, "sandboxes", id), filepath.Join(s.Root, "keys", id+".pem"), nil
}
func (s Store) protected(target, tree, key string, directory bool) error {
	for item := target; ; item = filepath.Dir(item) {
		st, err := os.Lstat(item)
		if err != nil {
			return ErrUntrusted
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUntrusted
		}
		payload := item == key || item == tree || strings.HasPrefix(item, tree+string(filepath.Separator))
		expected := uint32(0)
		if !payload && s.ancestorUID != nil && owner.Uid == *s.ancestorUID {
			expected = *s.ancestorUID
		}
		if payload {
			expected = s.MappedUID
		}
		if owner.Uid != expected || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || (payload && st.Mode().Perm()&0222 != 0) {
			return ErrUntrusted
		}
		if item != target || directory {
			if !st.IsDir() {
				return ErrUntrusted
			}
		} else if !st.Mode().IsRegular() || owner.Nlink != 1 {
			return ErrUntrusted
		}
		if item == "/" {
			break
		}
	}
	return nil
}
func (s Store) read(target, tree, key string, cap int) ([]byte, error) {
	if err := s.protected(target, tree, key, false); err != nil {
		return nil, err
	}
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUntrusted
	}
	file := os.NewFile(uintptr(fd), target)
	defer file.Close()
	before, err := os.Lstat(target)
	if err != nil {
		return nil, ErrUntrusted
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() > int64(cap) {
		return nil, ErrUntrusted
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(cap)+1))
	if err != nil || len(data) > cap {
		return nil, ErrUntrusted
	}
	return data, nil
}
func Digest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
func decode(b []byte, v any) error {
	if !utf8.Valid(b) {
		return ErrUntrusted
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrUntrusted
	}
	// Duplicates are not canonical authority. Compare decoded map key counts via
	// token walk rather than allowing last-key-wins interpretations across R/S.
	return rejectDuplicates(b)
}
func rejectDuplicates(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var visit func() error
	visit = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					name, ok := k.(string)
					if !ok || seen[name] {
						return ErrUntrusted
					}
					seen[name] = true
					if e := visit(); e != nil {
						return e
					}
				}
			} else if delim == '[' {
				for d.More() {
					if e := visit(); e != nil {
						return e
					}
				}
			} else {
				return ErrUntrusted
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if visit() != nil {
		return ErrUntrusted
	}
	return nil
}
func live(expiry string, now time.Time) bool {
	t, e := time.Parse(time.RFC3339Nano, expiry)
	return e == nil && now.Before(t)
}

var loopback = regexp.MustCompile(`^https://(127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$`)

func (s Store) signed(tree, key, name string, cap int) ([]byte, error) {
	b, e := s.read(filepath.Join(tree, name+".json"), tree, key, cap)
	if e != nil {
		return nil, e
	}
	sig, e := s.read(filepath.Join(tree, name+".sig"), tree, key, 256)
	if e != nil {
		return nil, e
	}
	kb, e := s.read(key, tree, key, 4096)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(kb)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrUntrusted
	}
	pub, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, ErrUntrusted
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	d := sha256.Sum256(b)
	if !ok || ec.Curve.Params().Name != "P-256" || !ecdsa.VerifyASN1(ec, d[:], sig) {
		return nil, ErrUntrusted
	}
	return b, nil
}
func (s Store) Bootstrap(box model.Sandbox, image string, now time.Time) (Bootstrap, error) {
	tree, key, e := s.Paths(box.ID)
	if e != nil {
		return Bootstrap{}, e
	}
	b, e := s.signed(tree, key, "bootstrap", 32768)
	if e != nil {
		return Bootstrap{}, e
	}
	var boot Bootstrap
	if decodeClosed(b, &boot) != nil || !safeID.MatchString(boot.CampaignID) || !safeID.MatchString(boot.Instance) || boot.ProfileID != "opencode" || !hash.MatchString(boot.ProfileDigest) || boot.SandboxID != box.ID || boot.SandboxGeneration != box.Generation || boot.ImageDigest != image || !hash.MatchString(boot.PluginSHA256) || !live(boot.ExpiresAt, now) {
		return Bootstrap{}, ErrUntrusted
	}
	if boot.FormatVersion == 3 {
		kb, err := s.read(key, tree, key, 4096)
		if err != nil || s.verifyNativeBootstrap(b, boot, kb, now) != nil {
			return Bootstrap{}, ErrUntrusted
		}
	} else if boot.FormatVersion == 2 {
		if boot.ProviderPolicyDigest != "" || boot.AccountingVersion != 0 || boot.AuthorityDigest != "" || boot.SourceBootstrap != nil || boot.Producer != nil || boot.ProducerPublicKeyBase64 != "" {
			return Bootstrap{}, ErrUntrusted
		}
		kb, e := s.read(key, tree, key, 4096)
		if e != nil || boot.Mode != "real_provider" || boot.Case == nil || !boot.Case.valid(boot.Ceilings) || boot.Origin != "https://api.openai.com" || !realTime.MatchString(boot.ExpiresAt) || boot.CASHA256 != "" || Digest(kb) != boot.Case.OperatorKeySHA256 {
			return Bootstrap{}, ErrUntrusted
		}
	} else {
		if boot.FormatVersion != 1 || boot.ProviderPolicyDigest != "" || boot.AccountingVersion != 0 || boot.AuthorityDigest != "" || boot.SourceBootstrap != nil || boot.Producer != nil || boot.ProducerPublicKeyBase64 != "" || boot.Mode != "" || boot.Case != nil || !hash.MatchString(boot.CASHA256) || !reflect.DeepEqual(boot.Ceilings, Ceilings) || !loopback.MatchString(boot.Origin) || strings.HasSuffix(boot.Origin, ":443") {
			return Bootstrap{}, ErrUntrusted
		}
		port, err := strconv.Atoi(boot.Origin[strings.LastIndex(boot.Origin, ":")+1:])
		if err != nil || port < 1 || port > 65535 {
			return Bootstrap{}, ErrUntrusted
		}
	}
	if boot.SandboxGeneration < 1 {
		return Bootstrap{}, ErrUntrusted
	}
	if !regexp.MustCompile(`(^|@)sha256:[a-f0-9]{64}$`).MatchString(image) {
		return Bootstrap{}, ErrUntrusted
	}
	for _, directory := range []string{"plugin", "snapshots", "preparations", "revocations"} {
		if s.protected(filepath.Join(tree, directory), tree, key, true) != nil {
			return Bootstrap{}, ErrUntrusted
		}
	}
	entries, err := os.ReadDir(filepath.Join(tree, "plugin"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "index.ts" {
		return Bootstrap{}, ErrUntrusted
	}
	for file, want := range map[string]string{"plugin/index.ts": boot.PluginSHA256, "ca.pem": boot.CASHA256} {
		if file == "ca.pem" && boot.Mode == "real_provider" {
			continue
		}
		b, e := s.read(filepath.Join(tree, file), tree, key, 131072)
		if e != nil || Digest(b) != want {
			return Bootstrap{}, ErrUntrusted
		}
	}
	return boot, nil
}
func (s Store) Select(box model.Sandbox, image string, entry model.CellServiceV3, workspace string, now time.Time) (Descriptor, error) {
	if !safeID.MatchString(entry.PreparationID) {
		return Descriptor{}, ErrUntrusted
	}
	boot, e := s.Bootstrap(box, image, now)
	if e != nil {
		return Descriptor{}, e
	}
	tree, key, _ := s.Paths(box.ID)
	tuple, e := entry.PreparedTuple()
	if e != nil {
		return Descriptor{}, e
	}
	td, e := tuple.Digest()
	if e != nil {
		return Descriptor{}, e
	}
	b, e := s.read(filepath.Join(tree, "preparations", entry.PreparationID+".json"), tree, key, 16384)
	if e != nil {
		return Descriptor{}, e
	}
	var descriptor Descriptor
	if decode(b, &descriptor) != nil || descriptor.FormatVersion != 1 || descriptor.PreparationID != entry.PreparationID || descriptor.PreparedTupleDigest != td || !hash.MatchString(descriptor.PolicyDigest) {
		return Descriptor{}, ErrUntrusted
	}
	name := "snapshots/" + strings.TrimPrefix(descriptor.PolicyDigest, "sha256:") + "/policy"
	b, e = s.signed(tree, key, name, 32768)
	if e != nil || Digest(b) != descriptor.PolicyDigest {
		return Descriptor{}, ErrUntrusted
	}
	var p Policy
	if decodeClosed(b, &p) != nil || p.PreparedTupleDigest != td || p.CampaignID != boot.CampaignID || p.SandboxID != boot.SandboxID || p.Instance != boot.Instance || p.Instance != entry.Instance || p.ProfileID != boot.ProfileID || p.ProfileDigest != boot.ProfileDigest || p.ProfileDigest != tuple.ProfileDigest || p.Origin != boot.Origin || p.PluginSHA256 != boot.PluginSHA256 || p.CASHA256 != boot.CASHA256 || p.Ceilings != boot.Ceilings || !live(p.ExpiresAt, now) || p.ProviderID != tuple.Authority.ProviderID || p.AuthMode != tuple.Authority.AuthMode || p.ModelID != tuple.Authority.ModelID || p.AuthMode != "api_key" || len(p.Preparations) != 1 {
		return Descriptor{}, ErrUntrusted
	}
	if boot.FormatVersion == 3 {
		kb, err := s.read(key, tree, key, 4096)
		if err != nil || s.verifyNativePolicy(b, boot, p, kb, now) != nil {
			return Descriptor{}, ErrUntrusted
		}
	} else if p.ProviderID != "openai" || !hash.MatchString(p.AuthorizationSHA256) || p.ProviderPolicyDigest != "" || p.AccountingVersion != 0 || p.SourcePolicy != nil || p.SourceBootstrapDigest != "" || p.SidecarBootstrapDigest != "" || p.AuthorizationBinding != "" {
		return Descriptor{}, ErrUntrusted
	}
	if boot.Mode == "real_provider" {
		if p.Run == nil || ((boot.FormatVersion != 3) && (p.FormatVersion != 3 || !p.Run.valid(boot, p))) || p.Mode != "real_provider" || !realTime.MatchString(p.ExpiresAt) ||
			p.Run.Tuple.Connection != entry.CredentialBinding || p.Run.Tuple.Profile.SetupOperationID != entry.Profile.SetupOperationID ||
			p.Run.Tuple.Profile.Revision != entry.Profile.ProfileRevision || s.realMaterial(box, p) != nil {
			return Descriptor{}, ErrUntrusted
		}
		if entry.LifecyclePhase == "execute" {
			selected, e := s.ReadQualificationActivation(box, boot, p, descriptor, now)
			a := selected.Execution
			if e != nil || entry.ExecutionGrant == nil || entry.PreparedReceiptDigest == nil || a.GrantID != entry.ExecutionGrant.GrantID || a.GrantDigest != CanonicalDigest(entry.ExecutionGrant) || a.PreparedReceiptDigest != *entry.PreparedReceiptDigest {
				return Descriptor{}, ErrUntrusted
			}
			x, _ := time.Parse(time.RFC3339Nano, a.ExpiresAt)
			g, _ := time.Parse(time.RFC3339Nano, entry.ExecutionGrant.ExpiresAt)
			if x.After(g) {
				return Descriptor{}, ErrUntrusted
			}
		}
	} else if p.FormatVersion != 2 || p.Mode != "" || p.Run != nil {
		return Descriptor{}, ErrUntrusted
	}
	prep := p.Preparations[0]
	if prep.PreparationID != entry.PreparationID || prep.SessionID != entry.NativeSessionID || prep.InputID != "msg_"+strings.TrimPrefix(entry.NativeSessionID, "ses_") || prep.Workspace != workspace || !strings.HasPrefix(workspace, "/home/agent/") || strings.HasPrefix(workspace, "/home/agent/.warpmetal") || filepath.Clean(workspace) != workspace {
		return Descriptor{}, ErrUntrusted
	}
	revdir := filepath.Join(tree, "revocations")
	if e = s.protected(revdir, tree, key, true); e != nil {
		return Descriptor{}, e
	}
	files, e := os.ReadDir(revdir)
	if e != nil {
		return Descriptor{}, ErrUntrusted
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			if !strings.HasSuffix(f.Name(), ".sig") {
				return Descriptor{}, ErrUntrusted
			}
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".json")
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) {
			return Descriptor{}, ErrUntrusted
		}
		b, e := s.signed(tree, key, "revocations/"+id, 16384)
		var r Revocation
		if e != nil || Digest(b) != "sha256:"+id || decode(b, &r) != nil || r.FormatVersion != 1 || r.CampaignID != boot.CampaignID || r.SandboxID != boot.SandboxID || !hash.MatchString(r.PolicyDigest) {
			return Descriptor{}, ErrUntrusted
		}
		if r.PolicyDigest == descriptor.PolicyDigest {
			return Descriptor{}, ErrUntrusted
		}
	}
	return descriptor, nil
}

// SelectedPolicy reuses the entire protected admission path; it cannot serve a
// raw arbitrary file to a producer or bypass the SQLite policy join in Runtime.
func (s Store) SelectedPolicy(box model.Sandbox, entry model.CellServiceV3, workspace string, now time.Time) (Bootstrap, Policy, Descriptor, error) {
	d, e := s.Select(box, box.ImageDigest, entry, workspace, now)
	if e != nil {
		return Bootstrap{}, Policy{}, Descriptor{}, e
	}
	b, e := s.Bootstrap(box, box.ImageDigest, now)
	if e != nil {
		return Bootstrap{}, Policy{}, Descriptor{}, e
	}
	tree, key, _ := s.Paths(box.ID)
	raw, e := s.signed(tree, key, "snapshots/"+d.PolicyDigest[7:]+"/policy", 32768)
	var p Policy
	if e != nil || decodeClosed(raw, &p) != nil {
		return Bootstrap{}, Policy{}, Descriptor{}, ErrUntrusted
	}
	return b, p, d, nil
}
