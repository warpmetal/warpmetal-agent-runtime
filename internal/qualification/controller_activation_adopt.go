package qualification

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"golang.org/x/sys/unix"
)

// Materialize ONLY the independently verified signed public original, AFTER its
// owning authenticated publication ACK. Existing signed snapshot layout and
// immutable helpers; no signer, key copy, overwrite, repair or second authority.
func (p *Producer) AdoptPublishedControllerActivation(s Store, box model.Sandbox, policy ControllerPolicy, prepared model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext, original ChildEnvelope[ControllerActivation], now time.Time) error {
	id, public, err := p.operatorDeliveryPin(s, box, policy.Case)
	if err != nil {
		return err
	}
	if verifyChildEnvelope(canonicalBytes(original), id, public) != nil || original.Payload.validate(policy, now) != nil || original.Payload.ValidateContext(policy, c) != nil || !reflect.DeepEqual(original.Payload.Admission.PreparedReceipt, prepared) {
		return ErrUntrusted
	}
	signature, err := base64.StdEncoding.DecodeString(original.Signature)
	if err != nil {
		return ErrUntrusted
	}
	payload := canonicalBytes(original.Payload)
	tree, key, err := s.Paths(box.ID)
	if err != nil || s.protected(tree, tree, key, true) != nil {
		return ErrUntrusted
	}
	root := filepath.Join(tree, "activations")
	if err = s.childProductDirectory(root, tree, key); err != nil {
		return err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUntrusted
	}
	defer unix.Close(fd)
	if unix.Flock(fd, unix.LOCK_EX) != nil {
		return ErrUntrusted
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	final := filepath.Join(root, "controller-"+prepared.PreparationID)
	if _, err = os.Lstat(final); err == nil {
		for name, expected := range map[string][]byte{"activation.json": payload, "activation.sig": signature} {
			got, err := s.read(filepath.Join(final, name), tree, key, 131072)
			if err != nil || !bytes.Equal(got, expected) {
				return ErrUntrusted
			}
		}
		return nil
	} else if !os.IsNotExist(err) {
		return ErrUntrusted
	}
	// A partial/torn deterministic generation is UNKNOWN permanently. No automatic
	// repair, second write, rename-over-original or cleanup is allowed.
	pending := filepath.Join(root, ".controller-"+prepared.PreparationID+".pending")
	if os.Mkdir(pending, 0700) != nil || syncChildProductDirectory(root) != nil {
		return ErrUntrusted
	}
	if s.childProductFile(filepath.Join(pending, "activation.json"), payload) != nil || s.childProductFile(filepath.Join(pending, "activation.sig"), signature) != nil || os.Chown(pending, int(s.MappedUID), -1) != nil || os.Chmod(pending, 0500) != nil || syncChildProductDirectory(pending) != nil || os.Rename(pending, final) != nil || syncChildProductDirectory(root) != nil {
		return ErrUntrusted
	}
	_, err = s.ReadControllerActivation(box, policy, prepared, now)
	return err
}
