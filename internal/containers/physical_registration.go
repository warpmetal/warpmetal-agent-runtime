package containers

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
)

func (p Podman) ObservePhysicalContainer(ctx context.Context, id string) (physicalgate.ContainerObservation, error) {
	var empty physicalgate.ContainerObservation
	if p.PhysicalStore == nil || p.QualificationRoot == "" {
		return empty, physicalgate.ErrPrerequisite
	}
	box, err := p.PhysicalStore.Sandbox(ctx, id)
	if err != nil || box == nil || box.Generation < 1 || box.ObservedGeneration != box.Generation || box.ObservedState != "running" {
		return empty, physicalgate.ErrPrerequisite
	}
	text, err := p.runOutput(ctx, true, "inspect", containerName(id))
	if err != nil {
		return empty, err
	}
	var rows []struct {
		ID     string `json:"Id"`
		Image  string
		Config struct{ Labels map[string]string }
		State  struct {
			PID     int `json:"Pid"`
			Running bool
		}
		Mounts []struct {
			Source, Destination string
			RW                  bool
			Options             []string
		}
	}
	if json.Unmarshal([]byte(text), &rows) != nil || len(rows) != 1 || !rows[0].State.Running || rows[0].State.PID < 1 {
		return empty, physicalgate.ErrPrerequisite
	}
	actual := rows[0].Image
	if !strings.HasPrefix(actual, "sha256:") {
		actual = "sha256:" + actual
	}
	selected, err := p.runOutput(ctx, true, "image", "inspect", "--format", "{{.Id}}", box.ImageDigest)
	expected := strings.TrimSpace(selected)
	if !strings.HasPrefix(expected, "sha256:") {
		expected = "sha256:" + expected
	}
	if err != nil || rows[0].Config.Labels[imageDigestLabel] != box.ImageDigest || actual != expected {
		return empty, physicalgate.ErrPrerequisite
	}
	mounted := false
	for _, m := range rows[0].Mounts {
		if m.Destination != physicalgate.ContainerDirectory {
			continue
		}
		if m.Source != physicalgate.HostDirectory || m.RW {
			return empty, physicalgate.ErrPrerequisite
		}
		for _, flag := range []string{"nodev", "nosuid", "noexec"} {
			have := false
			for _, o := range m.Options {
				if o == flag {
					have = true
				}
			}
			if !have {
				return empty, physicalgate.ErrPrerequisite
			}
		}
		mounted = true
	}
	if !mounted || p.verifyQualificationMounts(ctx, id) != nil {
		return empty, physicalgate.ErrPrerequisite
	}
	ready, err := p.ObserveCellWitness(ctx, id)
	if err != nil || !ready {
		return empty, physicalgate.ErrPrerequisite
	}
	dev, ino, err := physicalgate.EndpointIdentity()
	if err != nil {
		return empty, err
	}
	return physicalgate.ContainerObservation{SandboxID: id, Generation: box.Generation, ContainerID: rows[0].ID, ImageDigest: actual, InitPID: rows[0].State.PID, EndpointDevice: dev, EndpointInode: ino}, nil
}

func (p Podman) registerSupervisorPhysicalProcess(ctx context.Context, id string, raw []byte) error {
	if p.PhysicalProcesses == nil {
		return nil
	}
	var receipt struct {
		SchemaVersion                int `json:"schemaVersion"`
		Command, Instance, SandboxID string
		PID                          int
		Ready                        bool
		Phase                        string
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return physicalgate.ErrPrerequisite
	}
	if receipt.SchemaVersion != 1 || receipt.SandboxID != id || !receipt.Ready || receipt.PID < 1 || receipt.Instance == "" {
		return nil
	}
	switch receipt.Command {
	case "start", "restart", "status":
		return p.PhysicalProcesses.RegisterNative(ctx, id, receipt.Instance, receipt.PID)
	}
	return nil
}
