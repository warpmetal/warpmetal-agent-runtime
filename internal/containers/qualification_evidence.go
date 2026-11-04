package containers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

func (p Podman) qualificationEvidenceContext(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, workspace qualification.TrustedWorkspace) (*qualification.Producer, qualification.Policy, qualification.Descriptor, qualification.QualificationActivation, error) {
	if p.QualificationRoot == "" {
		return nil, qualification.Policy{}, qualification.Descriptor{}, qualification.QualificationActivation{}, nil
	}
	if e := p.verifyQualificationMounts(ctx, box.ID); e != nil {
		return nil, qualification.Policy{}, qualification.Descriptor{}, qualification.QualificationActivation{}, e
	}
	s, e := p.qualificationStore(ctx)
	if e != nil {
		return nil, qualification.Policy{}, qualification.Descriptor{}, qualification.QualificationActivation{}, e
	}
	boot, policy, d, e := s.SelectedPolicy(box, entry, workspace.ContainerRoot, time.Now())
	if e != nil {
		return nil, policy, d, qualification.QualificationActivation{}, e
	}
	if policy.Mode != "real_provider" {
		return nil, policy, d, qualification.QualificationActivation{}, nil
	}
	if e := p.verifyQualificationImage(ctx, box.ID, policy.Run.Tuple.Sandbox.ConfigDigest); e != nil {
		return nil, policy, d, qualification.QualificationActivation{}, e
	}
	producer, e := qualification.NewProducer(p.QualificationProducer, p.QualificationServerID, p.QualificationNodeTokenHash)
	if e != nil {
		return nil, policy, d, qualification.QualificationActivation{}, e
	}
	if boot.Case == nil || p.QualificationProducer.KeySHA256 == boot.Case.OperatorKeySHA256 {
		return nil, policy, d, qualification.QualificationActivation{}, qualification.ErrUntrusted
	}
	if policy.Run.Tuple.ServerID != p.QualificationServerID {
		return nil, policy, d, qualification.QualificationActivation{}, qualification.ErrUntrusted
	}
	actual, e := qualification.SelfBinaryDigest()
	if e != nil || actual != policy.Run.Tuple.Runtime.BinarySHA256 {
		return nil, policy, d, qualification.QualificationActivation{}, qualification.ErrUntrusted
	}
	a, e := s.ReadQualificationActivation(box, boot, policy, d, time.Now())
	if e == nil && a.Native != nil {
		allocation, err := s.QualificationPhysicalAllocation(box, *boot.Case, policy.Run.TupleDigest, time.Now())
		if err != nil {
			return nil, policy, d, a, err
		}
		a.PhysicalAllocation = &allocation
	}
	return producer, policy, d, a, e
}

func (p Podman) BeginCellQualificationEvidence(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, workspace qualification.TrustedWorkspace) error {
	producer, policy, d, a, e := p.qualificationEvidenceContext(ctx, box, entry, workspace)
	if e != nil || producer == nil {
		return e
	}
	return producer.Begin(d, a.Execution, policy.Run.Workload, workspace.HostRoot, workspace.Device, workspace.Inode, time.Now())
}

func (p Podman) CompleteCellQualificationEvidence(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, workspace qualification.TrustedWorkspace, receipt model.PreparedReceipt, report model.CellServiceReportV1, effect []byte) error {
	producer, policy, d, a, e := p.qualificationEvidenceContext(ctx, box, entry, workspace)
	if e != nil || producer == nil {
		return e
	}
	if report.ObservedState != "ready" || report.Child == nil || report.Child.State != "terminal" || report.Child.Outcome == nil || *report.Child.Outcome != "succeeded" || report.ReceiptDigest != qualification.Digest(effect) || entry.ExecutionGrant == nil || entry.ValidateExecutionAuthority(receipt) != nil {
		return qualification.ErrUntrusted
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output := &boundedBuffer{maximum: 2 * 1024 * 1024}
	diagnostic := &boundedBuffer{maximum: 16384}
	args := []string{"exec", "--user", "1000:1000", "--workdir", "/home/agent", containerName(box.ID), "/usr/local/bin/node", "--experimental-strip-types", "/usr/local/libexec/warpmetal-qualification-plugin/index.ts", "--collect-real-qualification", entry.PreparationID}
	if e = p.runRemoteStreams(bounded, nil, output, diagnostic, args...); e != nil || output.overflow || diagnostic.overflow {
		return qualification.ErrUntrusted
	}
	o, e := qualification.ParseObservations(output.Bytes())
	if e != nil {
		return e
	}
	grant, _ := json.Marshal(entry.ExecutionGrant)
	var object any
	_ = json.Unmarshal(grant, &object)
	grant, _ = json.Marshal(object)
	o.Blobs[a.Execution.GrantDigest] = base64.StdEncoding.EncodeToString(grant)
	_, e = producer.AttestQualification(policy, d, a, o, report.ReceiptDigest, workspace.HostRoot, workspace.Device, workspace.Inode, workspace.WorkspaceDigest, time.Now())
	return e
}
