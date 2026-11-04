package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Private transport of FIRST existing originals. This is not new signed
// authority: every signature/ACK/current input and stage is independently joined.
type childIntegrationCustody struct {
	GenerationDigest   string                    `json:"generationDigest"`
	EntryDigest        string                    `json:"entryDigest"`
	InputID            string                    `json:"inputId"`
	InputDigest        string                    `json:"inputDigest"`
	DeliveryPlanDigest string                    `json:"deliveryPlanDigest"`
	Stage              integrationStage          `json:"stage"`
	SourceReads        []ChildSourceReadOriginal `json:"sourceReads"`
}

func (p *Producer) currentIntegration(ctx context.Context, store Store, box model.Sandbox, w ChildProductWitness) (ChildProductControl, error) {
	var empty ChildProductControl
	if p == nil || p.key == nil || ctx.Err() != nil || w.Entry.LifecyclePhase != "execute" || w.Entry.Role != "worker" ||
		w.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) {
		return empty, ErrUntrusted
	}
	c, err := store.ReadChildProduct(box, w.Preparation.PreparationID, w, time.Now())
	if err != nil {
		return empty, err
	}
	if _, err = c.IntegrationTarget(); err != nil {
		return empty, err
	}
	return c, nil
}

func (p *Producer) StageIntegrationTarget(ctx context.Context, store Store, box model.Sandbox, w ChildProductWitness, root TrustedWorkspace, detail json.RawMessage, body []byte) error {
	c, err := p.currentIntegration(ctx, store, box, w)
	if err != nil {
		return err
	}
	if _, err = stageIntegrationTarget(ctx, w, c, root, detail, body, producerPlanJournal{p}, store.MappedUID); err != nil {
		return err
	}
	again, err := p.currentIntegration(ctx, store, box, w)
	if err != nil || !sameProduct(again, c) {
		return ErrUntrusted
	}
	return nil
}

func (p *Producer) ReadIntegrationSource(ctx context.Context, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness) (model.WorkflowObservationEnvelope, WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead WorkflowSourceCapture
	if w.SourceReadDelivery != nil {
		return empty, noRead, ErrUntrusted
	}
	c, err := p.currentIntegration(ctx, w.Authority, w.Sandbox, w.Product)
	if err != nil {
		return empty, noRead, err
	}
	envelope, read, err := p.ReadChildProductSource(ctx, call, op, w)
	if err != nil {
		return empty, noRead, err
	}
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		if CanonicalDigest(scope) != read.ScopeDigest {
			continue
		}
		if integrationSourceInputMatches(w.Product, c, scope, read.Bytes) != nil {
			return empty, noRead, ErrUntrusted
		}
		if childString(childFields(scope.Grant), "use") == "integration_target_artifact" {
			stage, err := p.readIntegrationStage(ctx, w.Product, c, w.Workspace)
			if err != nil || stage.SourceDevice != read.SourceDevice || stage.SourceInode != read.SourceInode {
				return empty, noRead, ErrUntrusted
			}
		}
		return envelope, read, nil
	}
	return empty, noRead, ErrUntrusted
}

func (p *Producer) RetainIntegrationSourceRead(ctx context.Context, w ChildProductWitness, c ChildProductControl, envelope model.WorkflowObservationEnvelope, read WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	if _, err := c.IntegrationTarget(); err != nil {
		return err
	}
	return p.retainChildSourceRead(ctx, w, c, envelope, read, receipt)
}
func (p *Producer) ReadIntegrationSourceReceipts(ctx context.Context, w ChildProductWitness, c ChildProductControl) ([]ChildSourceReadOriginal, error) {
	if _, err := c.IntegrationTarget(); err != nil {
		return nil, err
	}
	return p.readChildSourceReceipts(ctx, w, c)
}

func (p *Producer) readIntegrationStage(ctx context.Context, w ChildProductWitness, c ChildProductControl, root TrustedWorkspace) (integrationStage, error) {
	var empty integrationStage
	if _, err := c.IntegrationTarget(); err != nil {
		return empty, err
	}
	name := integrationStageName(w, c)
	detail, err := p.read(name+"-target.json", 65536)
	if err != nil {
		return empty, err
	}
	body, err := p.read(name+"-target.body", 8192)
	if err != nil {
		return empty, err
	}
	// Only the replay branch is permitted here; no missing-stage recreation.
	if _, err = p.read(name+".json", 65536); err != nil {
		return empty, err
	}
	return stageIntegrationTarget(ctx, w, c, root, detail, body, producerPlanJournal{p}, 0)
}

func (p *Producer) SealIntegrationDelivery(ctx context.Context, store Store, box model.Sandbox, w ChildProductWitness, root TrustedWorkspace) error {
	c, err := p.currentIntegration(ctx, store, box, w)
	if err != nil {
		return err
	}
	stage, err := p.readIntegrationStage(ctx, w, c, root)
	if err != nil {
		return err
	}
	reads, err := p.ReadIntegrationSourceReceipts(ctx, w, c)
	if err != nil {
		return err
	}
	d := c.Generation.Policy.Payload.IntegrationDelivery
	if len(reads) != len(d.Spans) {
		return ErrUntrusted
	}
	bundle := childIntegrationCustody{GenerationDigest: c.Descriptor.GenerationDigest, EntryDigest: CanonicalDigest(w.Entry), InputID: d.InputID, InputDigest: d.InputDigest, DeliveryPlanDigest: d.DeliveryPlanDigest, Stage: stage, SourceReads: reads}
	raw := canonicalBytes(bundle)
	if len(raw) > 512*1024 {
		return ErrUntrusted
	}
	// Retain host-private FIRST originals before the protected read-only export.
	if p.append("integration-custody-"+c.Descriptor.GenerationDigest[7:]+".json", raw) != nil {
		return ErrUntrusted
	}
	again, err := p.currentIntegration(ctx, store, box, w)
	if err != nil || !sameProduct(again, c) {
		return ErrUntrusted
	}
	if _, err = p.readIntegrationStage(ctx, w, c, root); err != nil {
		return err
	}
	return store.publishIntegrationCustody(ctx, box, w, c, raw)
}

func (s Store) publishIntegrationCustody(ctx context.Context, box model.Sandbox, w ChildProductWitness, c ChildProductControl, raw []byte) error {
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return err
	}
	again, err := s.ReadChildProduct(box, w.Preparation.PreparationID, w, time.Now())
	if err != nil || !sameProduct(again, c) || ctx.Err() != nil {
		return ErrUntrusted
	}
	dir := filepath.Join(tree, "product", "integration")
	if s.childProductDirectory(dir, tree, key) != nil {
		return ErrUntrusted
	}
	name := filepath.Join(dir, c.Descriptor.GenerationDigest[7:]+".json")
	if err = s.childProductFile(name, raw); errors.Is(err, os.ErrExist) {
		prior, e := s.read(name, tree, key, 512*1024)
		if e != nil || !bytes.Equal(prior, raw) {
			return ErrUntrusted
		}
	} else if err != nil {
		return ErrUntrusted
	}
	if syncChildProductDirectory(dir) != nil {
		return ErrUntrusted
	}
	again, err = s.ReadChildProduct(box, w.Preparation.PreparationID, w, time.Now())
	if err != nil || !sameProduct(again, c) || ctx.Err() != nil {
		return ErrUntrusted
	}
	return nil
}
