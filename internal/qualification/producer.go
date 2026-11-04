package qualification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ProducerConfig associates a host-only signer with the EXISTING registered
// Runtime. No automatic key generation, node re-registration or worker mount.
type ProducerConfig struct {
	KeyID         string `json:"keyId"`
	KeyPath       string `json:"keyPath"`
	KeySHA256     string `json:"keySHA256"`
	EvidenceRoot  string `json:"evidenceRoot"`
	ServerID      string `json:"serverId"`
	NodeTokenHash string `json:"nodeTokenHash"`
}
type Producer struct {
	config ProducerConfig
	key    *ecdsa.PrivateKey
}
type TrustedWorkspace struct {
	HostRoot, ContainerRoot, WorkspaceDigest string
	Device, Inode                            uint64
}

var rawHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func splitRoot(root string) []string { return strings.Split(root[1:], "/") }

func SelfBinaryDigest() (string, error) {
	name, e := os.Executable()
	if e != nil {
		return "", ErrUntrusted
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	// The Linux kernel's own proc link names the actually running inode even
	// after a deployment renames its path. This is not a caller filesystem link.
	if runtime.GOOS == "linux" {
		name = "/proc/self/exe"
		flags = unix.O_RDONLY | unix.O_CLOEXEC
	}
	fd, e := unix.Open(name, flags, 0)
	if e != nil {
		return "", ErrUntrusted
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 256*1024*1024 {
		return "", ErrUntrusted
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 256*1024*1024+1)); e != nil {
		return "", e
	}
	return "sha256:" + fmt.Sprintf("%x", h.Sum(nil)), nil
}

func rootPrivate(target string, directory bool) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return ErrUntrusted
	}
	for p := target; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return ErrUntrusted
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return ErrUntrusted
		}
		if p == target {
			if st.Mode().Perm()&0077 != 0 || (directory && !st.IsDir()) || (!directory && (!st.Mode().IsRegular() || owner.Nlink != 1)) {
				return ErrUntrusted
			}
		} else if !st.IsDir() {
			return ErrUntrusted
		}
		if p == "/" {
			return nil
		}
	}
}

// Validate checks the operator-supplied producer identity without touching the
// filesystem. It is the startup gate: a Runtime that must attest applications
// refuses to start without an exactly matching producer pin instead of silently
// refusing every receipt at runtime.
func (c *ProducerConfig) Validate(serverID, nodeTokenHash string) error {
	if c == nil {
		return errors.New("qualificationProducer is required")
	}
	if !safeID.MatchString(c.KeyID) {
		return errors.New("qualificationProducer.keyId is invalid")
	}
	if !hash.MatchString(c.KeySHA256) {
		return errors.New("qualificationProducer.keySHA256 is invalid")
	}
	if !safeID.MatchString(serverID) || c.ServerID != serverID {
		return errors.New("qualificationProducer.serverId does not match serverId")
	}
	if !rawHash.MatchString(nodeTokenHash) || c.NodeTokenHash != nodeTokenHash {
		return errors.New("qualificationProducer.nodeTokenHash does not match the node token")
	}
	if !filepath.IsAbs(c.KeyPath) || filepath.Clean(c.KeyPath) != c.KeyPath {
		return errors.New("qualificationProducer.keyPath must be an absolute clean path")
	}
	if !filepath.IsAbs(c.EvidenceRoot) || filepath.Clean(c.EvidenceRoot) != c.EvidenceRoot {
		return errors.New("qualificationProducer.evidenceRoot must be an absolute clean path")
	}
	return nil
}

func NewProducer(c *ProducerConfig, serverID, nodeTokenHash string) (*Producer, error) {
	if c.Validate(serverID, nodeTokenHash) != nil || rootPrivate(c.KeyPath, false) != nil || rootPrivate(c.EvidenceRoot, true) != nil {
		return nil, ErrUntrusted
	}
	fd, e := unix.Open(c.KeyPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUntrusted
	}
	f := os.NewFile(uintptr(fd), c.KeyPath)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return nil, ErrUntrusted
	}
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrUntrusted
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		key, e = x509.ParseECPrivateKey(block.Bytes)
	}
	if e != nil {
		return nil, ErrUntrusted
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve.Params().Name != "P-256" {
		return nil, ErrUntrusted
	}
	der, e := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if e != nil {
		return nil, ErrUntrusted
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if Digest(pub) != c.KeySHA256 {
		return nil, ErrUntrusted
	}
	return &Producer{*c, ec}, nil
}

type Baseline struct {
	PolicyDigest string `json:"policyDigest"`
	GrantDigest  string `json:"grantDigest"`
	HostRoot     string `json:"hostRoot"`
	RootDevice   uint64 `json:"rootDevice"`
	RootInode    uint64 `json:"rootInode"`
	Artifact     string `json:"artifact"`
	StartedAt    string `json:"startedAt"`
}

// Open every path component without following symlinks, not merely the leaf.
func confinedRoot(root string, device, inode uint64) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, ErrUntrusted
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range splitRoot(root) {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrUntrusted
		}
		fd = next
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != device || st.Ino != inode {
		unix.Close(fd)
		return nil, ErrUntrusted
	}
	return os.NewFile(uintptr(fd), root), nil
}
func (p *Producer) append(name string, b []byte) error {
	e := p.create(name, b)
	if errors.Is(e, syscall.EEXIST) {
		old, readErr := p.read(name, 2*1024*1024)
		if readErr != nil || !bytes.Equal(old, b) {
			return ErrUntrusted
		}
		return nil
	}
	return e
}

// Exclusive durable claim. Unlike append's exact-content replay, this cannot
// give two readers permission to dispatch the same operation.
func (p *Producer) create(name string, b []byte) error {
	if rootPrivate(p.config.EvidenceRoot, true) != nil || filepath.Base(name) != name || len(b) > 2*1024*1024 {
		return ErrUntrusted
	}
	target := filepath.Join(p.config.EvidenceRoot, name)
	fd, e := unix.Open(target, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), target)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	d, e := os.Open(p.config.EvidenceRoot)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (p *Producer) read(name string, cap int) ([]byte, error) {
	target := filepath.Join(p.config.EvidenceRoot, name)
	if filepath.Base(name) != name || rootPrivate(target, false) != nil {
		return nil, ErrUntrusted
	}
	fd, e := unix.Open(target, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(cap+1)))
	if e != nil || len(b) > cap {
		return nil, ErrUntrusted
	}
	return b, nil
}
func (p *Producer) Begin(d Descriptor, a Activation, w Workload, root string, device, inode uint64, now time.Time) error {
	name := d.PolicyDigest[7:] + "-baseline.json"
	if b, e := p.read(name, 16384); e == nil {
		var previous Baseline
		if decodeClosed(b, &previous) != nil || previous.PolicyDigest != d.PolicyDigest || previous.GrantDigest != a.GrantDigest || previous.HostRoot != root || previous.RootDevice != device || previous.RootInode != inode || previous.Artifact != w.ArtifactRelativePath {
			return ErrUntrusted
		}
		return nil
	}
	f, e := confinedRoot(root, device, inode)
	if e != nil {
		return e
	}
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstatat(int(f.Fd()), w.ArtifactRelativePath, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, syscall.ENOENT) {
		return ErrUntrusted
	}
	b, e := json.Marshal(Baseline{d.PolicyDigest, a.GrantDigest, root, device, inode, w.ArtifactRelativePath, now.UTC().Format(time.RFC3339Nano)})
	if e != nil {
		return e
	}
	return p.append(name, b)
}

type RequestObservation struct {
	ReservationID         string `json:"reservationId"`
	RequestIndex          int    `json:"requestIndex"`
	PhysicalIndex         int    `json:"physicalIndex"`
	OriginalRequestDigest string `json:"originalRequestDigest"`
	RequestDigest         string `json:"requestDigest"`
	ResponseDigest        string `json:"responseDigest"`
	WireResponseDigest    string `json:"wireResponseDigest"`
	DispatchDigest        string `json:"dispatchDigest"`
	ProviderRequestID     string `json:"providerRequestId"`
	ResponseID            string `json:"responseId"`
	ModelID               string `json:"modelId"`
	HTTPStatus            int    `json:"httpStatus"`
	InputTokens           int64  `json:"inputTokens"`
	OutputTokens          int64  `json:"outputTokens"`
	CachedInputTokens     int64  `json:"cachedInputTokens"`
	ReservedUSDMicros     int64  `json:"reservedUsdMicros"`
	ActualUSDMicros       int64  `json:"actualUsdMicros"`
	StartedAt             string `json:"startedAt"`
	CompletedAt           string `json:"completedAt"`
}
type ToolObservation struct {
	CallID            string          `json:"callId"`
	Arguments         string          `json:"arguments"`
	ArgumentsDigest   string          `json:"argumentsDigest"`
	StartedAt         string          `json:"startedAt"`
	Exit              int             `json:"exit"`
	Truncated         bool            `json:"truncated"`
	Timeout           bool            `json:"timeout"`
	Workspace         string          `json:"workspace"`
	ModelOutput       json.RawMessage `json:"modelOutput"`
	OutputDigest      string          `json:"outputDigest"`
	CompletedAt       string          `json:"completedAt"`
	ObservationDigest string          `json:"observationDigest"`
}
type Observations struct {
	FormatVersion       int                       `json:"formatVersion"`
	PolicyDigest        string                    `json:"policyDigest,omitempty"`
	Activation          *Activation               `json:"activation,omitempty"`
	SourcePolicyDigest  string                    `json:"sourcePolicyDigest,omitempty"`
	SidecarPolicyDigest string                    `json:"sidecarPolicyDigest,omitempty"`
	NativeActivation    *QualificationPublication `json:"nativeActivation,omitempty"`
	NativeBinarySHA256  string                    `json:"nativeBinarySHA256"`
	Requests            []RequestObservation      `json:"requests"`
	Tool                ToolObservation           `json:"tool"`
	Blobs               map[string]string         `json:"blobs"`
}

func ParseObservations(b []byte) (Observations, error) {
	var o Observations
	if len(b) > 2*1024*1024 || decodeClosed(b, &o) != nil {
		return o, ErrUntrusted
	}
	if o.FormatVersion == 2 {
		if workflowcontract.ValidateQualificationObservationsProvider(b) != nil {
			return o, ErrUntrusted
		}
	} else if o.FormatVersion != 1 || o.Activation == nil || o.NativeActivation != nil || o.SourcePolicyDigest != "" || o.SidecarPolicyDigest != "" {
		return o, ErrUntrusted
	}
	return o, nil
}
func cost(r RequestObservation) (int64, bool) {
	if r.InputTokens < 0 || r.InputTokens > 1047576 || r.OutputTokens < 0 || r.OutputTokens > 1000 || r.CachedInputTokens < 0 || r.CachedInputTokens > r.InputTokens {
		return 0, false
	}
	return ((r.InputTokens-r.CachedInputTokens)*400000 + r.CachedInputTokens*100000 + r.OutputTokens*1600000 + 999999) / 1000000, true
}

// Attest accepts only protected S observations joined to the existing local
// successful V3 terminal journal. It is not an arbitrary-payload signing API.
func (p *Producer) Attest(policy Policy, d Descriptor, a Activation, o Observations, terminalReportDigest string, root string, device, inode uint64, workspaceDigest string, now time.Time) (string, error) {
	return p.attestQualification(policy, d, QualificationActivation{Execution: a}, o, terminalReportDigest, root, device, inode, workspaceDigest, now)
}
func (p *Producer) attestQualification(policy Policy, d Descriptor, selected QualificationActivation, o Observations, terminalReportDigest string, root string, device, inode uint64, workspaceDigest string, now time.Time) (string, error) {
	a := selected.Execution
	indexName := d.PolicyDigest[7:] + "-evidence.json"
	if old, e := p.read(indexName, 16384); e == nil {
		var index struct {
			EvidenceDigest string `json:"evidenceDigest"`
		}
		if decodeClosed(old, &index) != nil || !hash.MatchString(index.EvidenceDigest) {
			return "", ErrUntrusted
		}
		b, e := p.read(index.EvidenceDigest[7:], 2*1024*1024)
		if e != nil || Digest(b) != index.EvidenceDigest {
			return "", ErrUntrusted
		}
		var evidence map[string]json.RawMessage
		if decode(b, &evidence) != nil {
			return "", ErrUntrusted
		}
		var att struct {
			Payload   json.RawMessage `json:"payload"`
			KeyID     string          `json:"keyId"`
			Signature string          `json:"signature"`
		}
		if decode(evidence["producerAttestation"], &att) != nil || att.KeyID != p.config.KeyID {
			return "", ErrUntrusted
		}
		sig, e := base64.StdEncoding.DecodeString(att.Signature)
		sum := sha256.Sum256(att.Payload)
		if e != nil || !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) {
			return "", ErrUntrusted
		}
		var payload map[string]json.RawMessage
		var receipt string
		if decode(att.Payload, &payload) != nil || json.Unmarshal(payload["terminalReportDigest"], &receipt) != nil || receipt != terminalReportDigest {
			return "", ErrUntrusted
		}
		return index.EvidenceDigest, nil
	}
	evidencePolicy, modelID, firstPhysical, bindingErr := qualificationObservationBinding(policy, d, selected, o)
	if bindingErr != nil {
		return "", bindingErr
	}
	r := policy.Run
	if r == nil || o.NativeBinarySHA256 != r.Tuple.Native.BinarySHA256 || len(o.Requests) != 2 || !hash.MatchString(terminalReportDigest) {
		return "", ErrUntrusted
	}
	baselineBytes, e := p.read(d.PolicyDigest[7:]+"-baseline.json", 16384)
	var baseline Baseline
	if e != nil || decodeClosed(baselineBytes, &baseline) != nil || baseline.HostRoot != root || baseline.RootDevice != device || baseline.RootInode != inode || baseline.GrantDigest != a.GrantDigest || baseline.Artifact != r.Workload.ArtifactRelativePath {
		return "", ErrUntrusted
	}
	blobs := map[string][]byte{}
	for id, encoded := range o.Blobs {
		b, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil || len(b) > 262144 || !hash.MatchString(id) || Digest(b) != id {
			return "", ErrUntrusted
		}
		blobs[id] = b
	}
	start, e := time.Parse(time.RFC3339Nano, o.Requests[0].StartedAt)
	if e != nil {
		return "", ErrUntrusted
	}
	begin, _ := time.Parse(time.RFC3339Nano, baseline.StartedAt)
	expiry, _ := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	previous := start
	for index, request := range o.Requests {
		x, xe := time.Parse(time.RFC3339Nano, request.StartedAt)
		y, ye := time.Parse(time.RFC3339Nano, request.CompletedAt)
		micros, valid := qualificationRequestCost(request, policy.FormatVersion == 4)
		if xe != nil || ye != nil || x.Before(previous) || y.Before(x) || y.After(now) || y.After(expiry) || start.Before(begin) || request.ReservationID != r.ReservationID || request.RequestIndex != index+1 || request.PhysicalIndex != firstPhysical+index || request.HTTPStatus != 200 || request.ModelID != modelID || request.ProviderRequestID == "" || request.ResponseID == "" || request.ReservedUSDMicros != RequestMicros || !valid || request.ActualUSDMicros != micros || micros > RequestMicros {
			return "", ErrUntrusted
		}
		for _, ref := range []string{request.OriginalRequestDigest, request.RequestDigest, request.ResponseDigest, request.WireResponseDigest, request.DispatchDigest} {
			if _, ok := blobs[ref]; !ok {
				return "", ErrUntrusted
			}
		}
		previous = y
	}
	if o.Requests[0].ProviderRequestID == o.Requests[1].ProviderRequestID || o.Tool.Exit != 0 || o.Tool.Truncated || o.Tool.Timeout || o.Tool.Workspace != policy.Preparations[0].Workspace || !safeID.MatchString(o.Tool.CallID) || blobs[o.Tool.ArgumentsDigest] == nil || blobs[o.Tool.ObservationDigest] == nil {
		return "", ErrUntrusted
	}
	f, e := confinedRoot(root, device, inode)
	if e != nil {
		return "", e
	}
	defer f.Close()
	fd, e := unix.Openat(int(f.Fd()), r.Workload.ArtifactRelativePath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", ErrUntrusted
	}
	artifact := os.NewFile(uintptr(fd), r.Workload.ArtifactRelativePath)
	defer artifact.Close()
	st, e := artifact.Stat()
	if e != nil {
		return "", ErrUntrusted
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || owner.Nlink != 1 || st.Size() > 262144 {
		return "", ErrUntrusted
	}
	b, e := io.ReadAll(io.LimitReader(artifact, 262145))
	if e != nil || len(b) > 262144 || Digest(b) != r.Workload.ExpectedArtifactSHA256 {
		return "", ErrUntrusted
	}
	blobs[Digest(b)] = b
	terminal, _ := json.Marshal(map[string]string{"artifact": r.Workload.ArtifactRelativePath, "sha256": Digest(b)})
	if Digest(terminal) != r.Workload.ExpectedTerminalJSONDigest {
		return "", ErrUntrusted
	}
	blobs[Digest(terminal)] = terminal
	observationDigest := o.Tool.ObservationDigest
	if policy.FormatVersion == 4 {
		observation, err := qualificationToolImportObservation(policy, d, selected, o, workspaceDigest, blobs)
		if err != nil {
			return "", err
		}
		observationDigest = Digest(observation)
		blobs[observationDigest] = observation
	}
	tool := map[string]any{"toolCallId": o.Tool.CallID, "tool": "shell", "argumentsDigest": o.Tool.ArgumentsDigest, "exitCode": 0, "workspaceDigest": workspaceDigest, "artifactRelativePath": r.Workload.ArtifactRelativePath, "artifactDigest": Digest(b), "artifactSize": len(b), "terminalJSONDigest": Digest(terminal), "toolObservationDigest": observationDigest}
	toolBytes := canonicalBytes(tool)
	tool["outcomeDigest"] = Digest(toolBytes)
	blobs[Digest(toolBytes)] = toolBytes
	identity := map[string]any{"executionId": a.ExecutionID, "operationId": "", "sessionId": policy.Preparations[0].SessionID, "inputId": policy.Preparations[0].InputID, "binarySHA256": o.NativeBinarySHA256}
	// Exact grant operation/attempt/fence are supplied as retained, verified bytes.
	grantBytes := blobs[a.GrantDigest]
	if grantBytes == nil {
		return "", ErrUntrusted
	}
	var grant map[string]any
	if decode(grantBytes, &grant) != nil || CanonicalDigest(grant) != a.GrantDigest {
		return "", ErrUntrusted
	}
	identity["operationId"], identity["attempt"], identity["fence"] = grant["operationId"], grant["attempt"], grant["fence"]
	payload := map[string]any{"formatVersion": 1, "qualificationId": r.QualificationID, "tuple": r.Tuple, "tupleDigest": r.TupleDigest, "permitDigest": r.CreatePermitDigest, "preparationId": d.PreparationID, "preparedTupleDigest": d.PreparedTupleDigest, "preparedReceiptDigest": a.PreparedReceiptDigest, "grantId": a.GrantID, "policyDigest": evidencePolicy, "nativeIdentity": identity, "requests": o.Requests, "toolOutcome": tool, "terminalReportDigest": terminalReportDigest, "startedAt": o.Requests[0].StartedAt, "completedAt": o.Requests[1].CompletedAt}
	for id, b := range blobs {
		if e := p.append(id[7:], b); e != nil {
			return "", e
		}
	}
	body := canonicalBytes(payload)
	sum := sha256.Sum256(body)
	sig, e := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if e != nil {
		return "", e
	}
	payload["producerAttestation"] = map[string]any{"payload": json.RawMessage(body), "keyId": p.config.KeyID, "signature": base64.StdEncoding.EncodeToString(sig)}
	evidence := canonicalBytes(payload)
	id := Digest(evidence)
	if e = p.append(id[7:], evidence); e != nil {
		return "", e
	}
	index, _ := json.Marshal(map[string]string{"evidenceDigest": id})
	return id, p.append(indexName, index)
}
