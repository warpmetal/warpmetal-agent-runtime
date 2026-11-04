package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// stageError adds a stable diagnostic stage around a pre-create refusal. It is
// purely observational: %w preserves errors.Is/errors.As and every caller's
// behavior; only the rendered error string gains one stage label.
func stageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("managed create stage %s: %w", stage, err)
}

func (p Podman) CellQualificationEnabled() bool { return p.QualificationRoot != "" }

func (p Podman) verifyQualificationMounts(ctx context.Context, id string) error {
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return err
	}
	tree, key, err := store.Paths(id)
	if err != nil {
		return err
	}
	text, err := p.runOutput(ctx, true, "inspect", containerName(id))
	if err != nil {
		return err
	}
	var rows []struct {
		Mounts []struct {
			Source, Destination string
			RW                  bool
			Options             []string
		}
	}
	if json.Unmarshal([]byte(text), &rows) != nil || len(rows) != 1 {
		return qualification.ErrUntrusted
	}
	for destination, source := range map[string]string{"/etc/warpmetal/qualification": tree, "/etc/warpmetal/qualification-public-key.pem": key} {
		found := false
		for _, m := range rows[0].Mounts {
			if m.Destination == destination {
				if m.Source != source || m.RW {
					return qualification.ErrUntrusted
				}
				for _, flag := range []string{"nodev", "nosuid", "noexec"} {
					present := false
					for _, o := range m.Options {
						if o == flag {
							present = true
						}
					}
					if !present {
						return qualification.ErrUntrusted
					}
				}
				found = true
			}
		}
		if !found {
			return qualification.ErrUntrusted
		}
	}
	return nil
}

// qualificationStore derives the subordinate owner from the REAL rootless
// service identity. keep-id:uid=1000 maps unshare UID 1 to container UID 0.
// No manifest-supplied mapping or generic unknown-owner fallback is accepted.
func (p Podman) qualificationStore(ctx context.Context) (qualification.Store, error) {
	s := qualification.Store{Root: p.QualificationRoot, ProducerConfig: p.QualificationProducer, ProducerServerID: p.QualificationServerID, ProducerNodeTokenHash: p.QualificationNodeTokenHash}
	if s.Root == "" {
		return s, nil
	}
	text, err := p.runOutput(ctx, false, "unshare", "cat", "/proc/self/uid_map")
	if err != nil {
		return s, err
	}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		inside, e1 := strconv.ParseUint(fields[0], 10, 32)
		outside, e2 := strconv.ParseUint(fields[1], 10, 32)
		length, e3 := strconv.ParseUint(fields[2], 10, 32)
		if e1 == nil && e2 == nil && e3 == nil && inside == 1 && length >= 1000 && outside > 0 {
			s.MappedUID = uint32(outside)
			return s, nil
		}
	}
	return s, qualification.ErrUntrusted
}

func (p Podman) managedCreateArguments(ctx context.Context, name string, box model.Sandbox, workspace, image string) ([]string, error) {
	args := createArgumentsWithLifecycle(name, box, workspace, image, p.cellLifecycle())
	if p.QualificationRoot == "" {
		return args, nil
	}
	if !box.Cell {
		return nil, stageError("cell-scope", qualification.ErrUntrusted)
	}
	store, err := p.qualificationStore(ctx)
	if err != nil {
		return nil, stageError("qualification-store", err)
	}
	if _, err = store.Bootstrap(box, image, time.Now()); err != nil {
		return nil, stageError("bootstrap", err)
	}
	tree, key, err := store.Paths(box.ID)
	if err != nil {
		return nil, stageError("paths", err)
	}
	// Insert before the image/entrypoint suffix; ordinary argv is unchanged.
	index := len(args) - 6
	mounts := []string{"--volume", tree + ":/etc/warpmetal/qualification:ro,nodev,nosuid,noexec", "--volume", key + ":/etc/warpmetal/qualification-public-key.pem:ro,nodev,nosuid,noexec"}
	if p.PhysicalProcesses != nil {
		if _, _, err := physicalgate.EndpointIdentity(); err != nil {
			return nil, stageError("physical-gate", err)
		}
		mounts = append(mounts, "--volume", physicalgate.HostDirectory+":"+physicalgate.ContainerDirectory+":ro,nodev,nosuid,noexec")
	}
	result := append([]string{}, args[:index]...)
	result = append(result, mounts...)
	return append(result, args[index:]...), nil
}

// VerifyCellQualification is called before every active preparation/report/
// execution replay. Returning nil with an empty digest is ONLY the disabled
// ordinary-production path. Cancellation must not call this admission guard.
func (p Podman) VerifyCellQualification(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, workspace string) (string, string, error) {
	if p.QualificationRoot == "" {
		return "", "", nil
	}
	if err := p.verifyQualificationMounts(ctx, box.ID); err != nil {
		return "", "", err
	}
	s, err := p.qualificationStore(ctx)
	if err != nil {
		return "", "", err
	}
	_, policy, d, err := s.SelectedPolicy(box, entry, workspace, time.Now())
	if err != nil {
		return "", "", fmt.Errorf("verify fixture selection: %w", err)
	}
	if policy.Mode == "real_provider" {
		if err := p.verifyQualificationImage(ctx, box.ID, policy.Run.Tuple.Sandbox.ConfigDigest); err != nil {
			return "", "", err
		}
	}
	return d.PreparedTupleDigest, d.PolicyDigest, nil
}

func (p Podman) verifyQualificationImage(ctx context.Context, id, configDigest string) error {
	text, e := p.runOutput(ctx, true, "inspect", "--format", "{{.Image}}", containerName(id))
	if e != nil {
		return qualification.ErrUntrusted
	}
	actual := strings.TrimSpace(text)
	if !strings.HasPrefix(actual, "sha256:") {
		actual = "sha256:" + actual
	}
	if actual != configDigest {
		return qualification.ErrUntrusted
	}
	return nil
}
