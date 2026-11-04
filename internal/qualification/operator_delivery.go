package qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

var ErrOperatorDeliveryPending = errors.New("expected public operator original not delivered")

// Fixed public delivery leaves in EXISTING Store.Paths. A missing/unsafe anchor
// is never absence. No configurable path, key/approval loader or signing entry.
func (s Store) readExpectedPublicOriginal(boxID, name string, bound int) ([]byte, error) {
	tree, key, err := s.Paths(boxID)
	if err != nil || filepath.Base(name) != name || s.protected(tree, tree, key, true) != nil || s.protected(key, tree, key, false) != nil {
		return nil, ErrUntrusted
	}
	path := filepath.Join(tree, name)
	if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, ErrOperatorDeliveryPending
	} else if err != nil {
		return nil, err
	}
	raw, err := s.read(path, tree, key, bound)
	if err != nil {
		return nil, err
	}
	if decode(raw, new(map[string]json.RawMessage)) != nil || !bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) {
		return nil, ErrUntrusted
	}
	return raw, nil
}

// Independent current pin, not envelope-selected identity. SAME root-private
// producer evidence authority and Store.Paths public key MUST agree. Only public
// bytes are read here; no execution operator private key/config is ever loaded.
func (p *Producer) operatorDeliveryPin(s Store, box model.Sandbox, c RealCase) (string, []byte, error) {
	if p == nil || !c.typed() {
		return "", nil, ErrUntrusted
	}
	anchor, err := p.read("physical-gate-authority.json", 65536)
	if err != nil {
		return "", nil, ErrUntrusted
	}
	public, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return "", nil, ErrUntrusted
	}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return "", nil, err
	}
	other, err := s.read(key, tree, key, 4096)
	if err != nil {
		return "", nil, ErrUntrusted
	}
	id, err := verifyOperatorDeliveryPin(p.config, c, anchor, public, other)
	return id, public, err
}

// Pure verification follows the protected reads above. These bytes cannot be
// selected by an envelope or supplied through a production caller/config path.
func verifyOperatorDeliveryPin(config ProducerConfig, c RealCase, anchor, public, storeKey []byte) (string, error) {
	definition := "authority2"
	if c.FormatVersion == 3 {
		definition = "authority3"
	}
	if !c.typed() || workflowcontract.Validate(c.contract(), definition, anchor) != nil {
		return "", ErrUntrusted
	}
	fields := childFields(anchor)
	pin, producerPin := childFields(fields["operator"]), childFields(fields["producer"])
	if Digest(public) != c.OperatorKeySHA256 || Digest(public) == config.KeySHA256 || childString(pin, "keyId") == config.KeyID || childString(producerPin, "keyId") != config.KeyID || childString(producerPin, "keySHA256") != strings.TrimPrefix(config.KeySHA256, "sha256:") || childString(producerPin, "nodeTokenHash") != config.NodeTokenHash || childString(pin, "keySHA256") != strings.TrimPrefix(Digest(public), "sha256:") || !sameProduct(fields["case"], c) || !bytes.Equal(storeKey, public) || !safeID.MatchString(childString(pin, "keyId")) {
		return "", ErrUntrusted
	}
	return childString(pin, "keyId"), nil
}

func controllerDeliveryPrepared(policy ControllerPolicy, prepared model.ControllerPreparedReceipt) error {
	if policy.FormatVersion == 6 {
		return policy.ValidatePreparedReceipt(prepared)
	}
	return prepared.Validate()
}

func controllerGrantDeliveryContext(box model.Sandbox, policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext) error {
	if controllerDeliveryPrepared(policy, prepared) != nil || prepared.PreparedTuple.Owner.SandboxID != box.ID || policy.ValidateContext(c) != nil || c.PreparationID != prepared.PreparationID {
		return ErrUntrusted
	}
	return nil
}

func (p *Producer) ReadControllerGrantDelivery(s Store, box model.Sandbox, policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext, now time.Time) (model.ControllerGrantEnvelope, error) {
	var out model.ControllerGrantEnvelope
	if controllerGrantDeliveryContext(box, policy, prepared, c) != nil {
		return out, ErrUntrusted
	}
	id, public, err := p.operatorDeliveryPin(s, box, policy.Case)
	if err != nil {
		return out, err
	}
	raw, err := s.readExpectedPublicOriginal(box.ID, "controller-activity-grant-"+prepared.PreparationID+".json", 65536)
	if err != nil {
		return out, err
	}
	return verifyControllerGrantDelivery(raw, id, public, policy, prepared, c, now)
}

func verifyControllerGrantDelivery(raw []byte, id string, public []byte, policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext, now time.Time) (model.ControllerGrantEnvelope, error) {
	var out model.ControllerGrantEnvelope
	if decode(raw, &out) != nil || verifyChildEnvelope(raw, id, public) != nil {
		return out, ErrUntrusted
	}
	g := out.Payload
	payload, _ := json.Marshal(g)
	if workflowcontract.Validate(workflowcontract.Producer, "controllerActivityGrant", payload) != nil || g.PreparationID != prepared.PreparationID || g.PreparedReceiptDigest != prepared.PreparedReceiptDigest || g.PolicyDigest != CanonicalDigest(policy) || g.CaseID != policy.Case.CaseID || g.CaseManifestDigest != policy.Case.CaseManifestDigest || g.PhysicalIndex != c.PhysicalIndex || !live(g.DeadlineAt, now) || !live(g.ExpiresAt, now) {
		return out, ErrUntrusted
	}
	return out, nil
}

func controllerActivationDeliveryContext(policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext) error {
	if controllerDeliveryPrepared(policy, prepared) != nil || policy.ValidateContext(c) != nil {
		return ErrUntrusted
	}
	return nil
}

func (p *Producer) ReadControllerActivationDelivery(s Store, box model.Sandbox, policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext, now time.Time) (ChildEnvelope[ControllerActivation], error) {
	var out ChildEnvelope[ControllerActivation]
	if controllerActivationDeliveryContext(policy, prepared, c) != nil {
		return out, ErrUntrusted
	}
	id, public, err := p.operatorDeliveryPin(s, box, policy.Case)
	if err != nil {
		return out, err
	}
	raw, err := s.readExpectedPublicOriginal(box.ID, "controller-activation-envelope-"+prepared.PreparationID+".json", 131072)
	if err != nil {
		return out, err
	}
	return verifyControllerActivationDelivery(raw, id, public, policy, prepared, c, now)
}

func verifyControllerActivationDelivery(raw []byte, id string, public []byte, policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext, now time.Time) (ChildEnvelope[ControllerActivation], error) {
	var out ChildEnvelope[ControllerActivation]
	if decode(raw, &out) != nil || verifyChildEnvelope(raw, id, public) != nil || out.Payload.validate(policy, now) != nil || out.Payload.ValidateContext(policy, c) != nil || !reflect.DeepEqual(out.Payload.Admission.PreparedReceipt, prepared) {
		return out, ErrUntrusted
	}
	return out, nil
}

// Original policy intent is supplied by the authenticated owning backend, never
// inferred from these envelopes. Signature/scope/receipt/expiry precede owning POST.
func (p *Producer) ReadChildPolicyDelivery(s Store, box model.Sandbox, handle model.IntentHandle, preparedID, stage string, intent json.RawMessage, now time.Time) (json.RawMessage, error) {
	if !safeID.MatchString(handle.HandleID) || !safeID.MatchString(preparedID) || (stage != "prepare" && stage != "product") || workflowcontract.Validate(workflowcontract.Budget, "policySigningIntent", intent) != nil {
		return nil, ErrUntrusted
	}
	basis := childFields(intent)
	payload := basis["payload"]
	var c RealCase
	if decode(childFields(payload)["case"], &c) != nil || childString(basis, "handleId") != handle.HandleID || childString(basis, "stage") != stage {
		return nil, ErrUntrusted
	}
	id, public, err := p.operatorDeliveryPin(s, box, c)
	if err != nil {
		return nil, err
	}
	raw, err := s.readExpectedPublicOriginal(box.ID, "child-"+stage+"-policy-request-"+handle.HandleID+".json", 256*1024)
	if err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.Budget, "policyAcceptRequest", raw) != nil {
		return nil, ErrUntrusted
	}
	request := childFields(raw)
	if childString(request, "stage") != stage {
		return nil, ErrUntrusted
	}
	preparation := childFields(request["preparationPolicy"])["payload"]
	if verifyChildEnvelope(request["preparationPolicy"], id, public) != nil || !live(childString(childFields(preparation), "expiresAt"), now) || childString(childFields(childFields(preparation)["preparation"]), "preparationId") != preparedID || !sameProduct(childFields(preparation)["handle"], handle) {
		return nil, ErrUntrusted
	}
	if stage == "prepare" {
		if !sameProduct(preparation, payload) {
			return nil, ErrUntrusted
		}
	} else {
		if verifyChildEnvelope(request["policy"], id, public) != nil || verifyChildEnvelope(request["policyBinding"], id, public) != nil || !sameProduct(childFields(request["policy"])["payload"], payload) || !sameProduct(childFields(request["policyBinding"])["payload"], basis["policyBinding"]) || !live(childString(childFields(payload), "expiresAt"), now) {
			return nil, ErrUntrusted
		}
	}
	return raw, nil
}

func (p *Producer) ReadChildActivationDelivery(s Store, box model.Sandbox, handle model.IntentHandle, c RealCase, intent json.RawMessage, now time.Time) (json.RawMessage, error) {
	if workflowcontract.Validate(workflowcontract.Budget, "activationSigningIntent", intent) != nil || childString(childFields(intent), "handleId") != handle.HandleID {
		return nil, ErrUntrusted
	}
	id, public, err := p.operatorDeliveryPin(s, box, c)
	if err != nil {
		return nil, err
	}
	raw, err := s.readExpectedPublicOriginal(box.ID, "child-activation-request-"+handle.HandleID+".json", 256*1024)
	if err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.Budget, "activationAcceptRequest", raw) != nil {
		return nil, ErrUntrusted
	}
	request, basis := childFields(raw), childFields(intent)
	payload := childFields(request["activation"])["payload"]
	if verifyChildEnvelope(request["activation"], id, public) != nil || !sameProduct(payload, basis["payload"]) || !sameProduct(request["authorizationObservation"], basis["authorizationObservation"]) || !live(childString(childFields(payload), "expiresAt"), now) {
		return nil, ErrUntrusted
	}
	return raw, nil
}

// Exact existing handoffs only, not an approval file or signer callback. The caller
// validates the owning intent and retains its durable result BEFORE export.
func (p *Producer) ExportControllerActivationHandoff(preparedID string, raw []byte) error {
	if p == nil || !safeID.MatchString(preparedID) || decode(raw, new(map[string]json.RawMessage)) != nil {
		return ErrUntrusted
	}
	return p.append("controller-activation-handoff-"+preparedID+".json", raw)
}
func (p *Producer) ExportChildSigningIntent(handleID, stage string, raw []byte) error {
	if p == nil || !safeID.MatchString(handleID) {
		return ErrUntrusted
	}
	definition, name := "policySigningIntent", "child-"+stage+"-policy-intent-"+handleID+".json"
	if stage == "activation" {
		definition, name = "activationSigningIntent", "child-activation-intent-"+handleID+".json"
	} else if stage != "prepare" && stage != "product" {
		return ErrUntrusted
	}
	if workflowcontract.Validate(workflowcontract.Budget, definition, raw) != nil || childString(childFields(raw), "handleId") != handleID {
		return ErrUntrusted
	}
	return p.append(name, raw)
}
