package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// A consumer of the manager's FIRST receipt, not an allowance owner. There is
// deliberately no begin/claim/sign/counter update, live transition, or fallback.
func (p *Producer) readValidationDispatch(attempt string) ([]byte, error) {
	if p == nil || !safeID.MatchString(attempt) || rootPrivate(p.config.EvidenceRoot, true) != nil {
		return nil, ErrUntrusted
	}
	root, err := unix.Open(p.config.EvidenceRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUntrusted
	}
	defer unix.Close(root)
	dir, err := unix.Openat(root, "validation-attempts", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUntrusted
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil || st.Uid != 0 || st.Mode&0077 != 0 {
		return nil, ErrUntrusted
	}
	fd, err := unix.Openat(dir, attempt+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUntrusted
	}
	f := os.NewFile(uintptr(fd), "manager-validation-dispatch-original")
	defer f.Close()
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 1 || st.Size > 65536 {
		return nil, ErrUntrusted
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrUntrusted
	}
	return raw, nil
}

func verifyValidationDispatch(raw, inventoryRaw, authority, operator []byte, now time.Time) error {
	if workflowcontract.Validate(workflowcontract.ValidationDispatch, "dispatchReceiptEnvelope", raw) != nil ||
		workflowcontract.Validate(workflowcontract.CompleteExecutionInventory, "completeExecutionInventoryEnvelope", inventoryRaw) != nil ||
		!bytes.Equal(raw, canonicalBytes(json.RawMessage(raw))) || !bytes.Equal(inventoryRaw, canonicalBytes(json.RawMessage(inventoryRaw))) {
		return ErrUntrusted
	}
	// Key ID and pin come from the protected authority, not either signed input.
	op := childFields(childFields(authority)["operator"])
	if childString(op, "keySHA256") != Digest(operator)[7:] ||
		verifyChildEnvelope(raw, childString(op, "keyId"), operator) != nil ||
		verifyChildEnvelope(inventoryRaw, childString(op, "keyId"), operator) != nil {
		return ErrUntrusted
	}
	receipt := childFields(childFields(raw)["payload"])
	inventory := childFields(childFields(inventoryRaw)["payload"])
	for _, field := range []string{"validationWindow", "attemptId", "candidateInventoryDigest", "scope"} {
		if !sameProduct(receipt[field], inventory[field]) {
			return ErrUntrusted
		}
	}
	claimed, ce := time.Parse(time.RFC3339Nano, childString(receipt, "claimedAt"))
	opened, oe := time.Parse(time.RFC3339Nano, childString(childFields(receipt["validationWindow"]), "openedAt"))
	issued, ie := time.Parse(time.RFC3339Nano, childString(inventory, "issuedAt"))
	expires, ee := time.Parse(time.RFC3339Nano, childString(inventory, "expiresAt"))
	if ce != nil || oe != nil || ie != nil || ee != nil || claimed.Before(opened) || claimed.After(now) || issued.After(now) || !now.Before(expires) {
		return ErrUntrusted
	}
	return nil
}

// All domains of an attempt consume the SAME installed original. Immutable
// associations are evidence fences in the existing Store, never consumption or
// reconstructed allowance. F1 separately binds the ordinal in its owning journal.
func (p *Producer) verifyCurrentValidationDispatch(ctx context.Context, store *state.Store, inventoryRaw []byte, operatorDigest string) error {
	if p == nil || store == nil || ctx.Err() != nil {
		return ErrUntrusted
	}
	inventory := childFields(childFields(inventoryRaw)["payload"])
	authority, err := p.read("physical-gate-authority.json", 65536)
	if err != nil {
		return ErrUntrusted
	}
	operator, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || Digest(operator) != operatorDigest {
		return ErrUntrusted
	}
	attempt := childString(inventory, "attemptId")
	raw, err := p.readValidationDispatch(attempt)
	if err != nil || verifyValidationDispatch(raw, inventoryRaw, authority, operator, time.Now()) != nil {
		return ErrUntrusted
	}
	payload := childFields(childFields(raw)["payload"])
	originalBaseline, be := p.paidOriginal(childString(payload, "baselineEnvelopeDigest"))
	if be != nil || verifyValidationBaseline(originalBaseline, raw, authority, operator) != nil {
		return ErrUntrusted
	}
	window := CanonicalDigest(payload["validationWindow"])
	ordinal := string(payload["integratedOrdinal"])
	baseline := canonicalBytes(map[string]any{"baselineEnvelopeDigest": payload["baselineEnvelopeDigest"], "operatorKeySHA256": Digest(operator)})
	if err = store.RetainPhysicalFact(ctx, "validation_dispatch_baseline_"+window[7:], baseline); err != nil {
		return err
	}
	// First receipt replay is exact, including the original signature. A changed
	// receipt cannot be made current by changing a domain/selection/alias.
	if err = store.RetainPhysicalFact(ctx, "validation_dispatch_ordinal_"+window[7:]+"_"+ordinal, raw); err != nil {
		return err
	}
	if err = store.RetainPhysicalFact(ctx, "validation_dispatch_attempt_"+Digest([]byte(attempt))[7:], raw); err != nil {
		return err
	}
	again, err := p.readValidationDispatch(attempt)
	currentAuthority, ae := p.read("physical-gate-authority.json", 65536)
	currentOperator, oe := p.read("physical-gate-operator.pem", 4096)
	currentInventory, ie := p.read("complete-execution-inventory.json", 65536)
	if err != nil || ae != nil || oe != nil || ie != nil || !bytes.Equal(raw, again) || !bytes.Equal(authority, currentAuthority) || !bytes.Equal(operator, currentOperator) || !bytes.Equal(inventoryRaw, currentInventory) || ctx.Err() != nil {
		return ErrUntrusted
	}
	return nil
}
