package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"golang.org/x/sys/unix"
)

// AdoptChildProduct publishes only an independently verified fixed-node delivery
// under Store.Paths. It does not provision a key/witness, sign, reserve, grant,
// dispatch or replace descriptor1. The reconciler caller must independently
// re-observe mounts/current installed/qualification witnesses before every use;
// missing final052/current acceptance still denies that connected caller.
func (s Store) AdoptChildProduct(box model.Sandbox, delivery model.ChildProductDelivery, w ChildProductWitness, now time.Time) error {
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return ErrUntrusted
	}
	publicPEM, err := s.read(key, tree, key, 4096)
	if err != nil {
		return ErrUntrusted
	}
	c, err := VerifyChildProductControl(delivery.Bytes(), w, publicPEM, now)
	if err != nil || delivery.PreparationID() != c.Descriptor.PreparationID ||
		c.Generation.PreparationPolicy.Payload.Applicability.SandboxID != box.ID ||
		c.Generation.PreparationPolicy.Payload.Applicability.SandboxGeneration != box.Generation {
		return ErrUntrusted
	}
	if s.protected(tree, tree, key, true) != nil || s.protected(filepath.Join(tree, "preparations"), tree, key, true) != nil {
		return ErrUntrusted
	}
	// Serialize selector compare-and-advance on the existing protected directory,
	// not a new writable grant file or child-controlled lock path.
	fd, err := unix.Open(filepath.Join(tree, "preparations"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUntrusted
	}
	defer unix.Close(fd)
	if unix.Flock(fd, unix.LOCK_EX) != nil {
		return ErrUntrusted
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	selector := filepath.Join(tree, "preparations", c.Descriptor.PreparationID+".json")
	if _, err := os.Lstat(selector); err == nil {
		old, err := s.read(selector, tree, key, 65536)
		var priorDescriptor ChildProductDescriptor
		if err != nil || workflowcontract.ValidateChildProduct("controlDescriptor", old) != nil || decode(old, &priorDescriptor) != nil || priorDescriptor.FormatVersion != 2 ||
			priorDescriptor.PreparationID != c.Descriptor.PreparationID || !hash.MatchString(priorDescriptor.GenerationDigest) {
			return ErrUntrusted
		}
		if sameProduct(priorDescriptor, c.Descriptor) {
			_, err := s.ReadChildProduct(box, c.Descriptor.PreparationID, w, now)
			return err
		}
		priorBytes, err := s.read(filepath.Join(tree, "product", "snapshots", priorDescriptor.GenerationDigest[7:], "control.json"), tree, key, 512*1024)
		var prior ChildProductControl
		prior.Descriptor = priorDescriptor
		if err != nil || Digest(priorBytes) != priorDescriptor.GenerationDigest || decode(priorBytes, &prior.Generation) != nil || validateChildGeneration(prior.Generation, priorBytes) != nil || childProductAdvance(prior, c) != nil {
			return ErrUntrusted
		}
	} else if !os.IsNotExist(err) || c.Generation.Phase != "prepare" {
		return ErrUntrusted // first adoption cannot start at execute
	}
	var wire struct {
		FormatVersion int             `json:"formatVersion"`
		Descriptor    json.RawMessage `json:"descriptor"`
		Generation    json.RawMessage `json:"generation"`
	}
	if decode(delivery.Bytes(), &wire) != nil {
		return ErrUntrusted
	}
	generation := canonicalBytes(wire.Generation)
	if Digest(generation) != c.Descriptor.GenerationDigest {
		return ErrUntrusted
	}
	for _, rel := range []string{"product", "product/snapshots", "product/adoptions", "blobs"} {
		if s.childProductDirectory(filepath.Join(tree, rel), tree, key) != nil {
			return ErrUntrusted
		}
	}
	// Exact immutable instruction transport bytes; never append reviewer text or
	// stage original foreign source files in Work/control. Existing blob namespace.
	inputBlob := filepath.Join(tree, "blobs", Digest(w.Input)[7:])
	if _, err := os.Lstat(inputBlob); os.IsNotExist(err) {
		if s.childProductFile(inputBlob, w.Input) != nil || syncChildProductDirectory(filepath.Dir(inputBlob)) != nil {
			return ErrUntrusted
		}
	} else {
		raw, err := s.read(inputBlob, tree, key, 16384)
		if err != nil || !bytes.Equal(raw, w.Input) {
			return ErrUntrusted
		}
	}
	if len(w.ProducerPEM) > 0 {
		pub := filepath.Join(tree, "blobs", Digest(w.ProducerPEM)[7:])
		if _, err := os.Lstat(pub); os.IsNotExist(err) {
			if s.childProductFile(pub, w.ProducerPEM) != nil || syncChildProductDirectory(filepath.Dir(pub)) != nil {
				return ErrUntrusted
			}
		} else {
			raw, err := s.read(pub, tree, key, 4096)
			if err != nil || !bytes.Equal(raw, w.ProducerPEM) {
				return ErrUntrusted
			}
		}
	}
	adoption := ChildProductNativeRecord{FormatVersion: 1, GenerationDigest: c.Descriptor.GenerationDigest, Entry: w.Entry, Applicability: w.Applicability, Qualification: w.Qualification, Root: w.Root, AuthorizedUntil: w.AuthorizedUntil.Format(time.RFC3339Nano), SourceContinuation: w.SourceContinuation}
	adoptionPath := filepath.Join(tree, "product", "adoptions", c.Descriptor.GenerationDigest[7:]+".json")
	if _, err := os.Lstat(adoptionPath); os.IsNotExist(err) {
		if s.childProductFile(adoptionPath, canonicalBytes(adoption)) != nil || syncChildProductDirectory(filepath.Dir(adoptionPath)) != nil {
			return ErrUntrusted
		}
	} else {
		raw, err := s.read(adoptionPath, tree, key, 65536)
		if err != nil || !bytes.Equal(raw, canonicalBytes(adoption)) {
			return ErrUntrusted
		}
	}
	snapshots := filepath.Join(tree, "product", "snapshots")
	final := filepath.Join(snapshots, c.Descriptor.GenerationDigest[7:])
	if _, err := os.Lstat(final); err == nil {
		raw, err := s.read(filepath.Join(final, "control.json"), tree, key, 512*1024)
		if err != nil || !bytes.Equal(raw, generation) {
			return ErrUntrusted
		}
	} else if !os.IsNotExist(err) {
		return ErrUntrusted
	} else {
		// Deterministic exclusive pending name fences unknown/torn publication.
		// A later attempt never removes/repairs it or replaces retained bytes.
		pending := filepath.Join(snapshots, ".pending-"+c.Descriptor.GenerationDigest[7:])
		if os.Mkdir(pending, 0700) != nil || syncChildProductDirectory(snapshots) != nil {
			return ErrUntrusted
		}
		if s.childProductFile(filepath.Join(pending, "control.json"), generation) != nil ||
			os.Chown(pending, int(s.MappedUID), -1) != nil || os.Chmod(pending, 0500) != nil || syncChildProductDirectory(pending) != nil ||
			os.Rename(pending, final) != nil || syncChildProductDirectory(snapshots) != nil {
			return ErrUntrusted
		}
	}
	// The complete immutable generation is durable BEFORE the index advances.
	// A leftover pending selector stays unknown/held; no automatic overwrite.
	pendingSelector := filepath.Join(tree, "preparations", ".product-"+c.Descriptor.GenerationDigest[7:]+".pending")
	if s.childProductFile(pendingSelector, canonicalBytes(c.Descriptor)) != nil ||
		unix.Fsync(fd) != nil || os.Rename(pendingSelector, selector) != nil || unix.Fsync(fd) != nil {
		return ErrUntrusted
	}
	_, err = s.ReadChildProduct(box, c.Descriptor.PreparationID, w, now)
	return err
}

func syncChildProductDirectory(name string) error {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUntrusted
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func (s Store) childProductDirectory(name, tree, key string) error {
	if err := os.Mkdir(name, 0700); err == nil {
		if os.Chown(name, int(s.MappedUID), -1) != nil || os.Chmod(name, 0500) != nil || syncChildProductDirectory(filepath.Dir(name)) != nil {
			return ErrUntrusted
		}
	} else if !os.IsExist(err) {
		return ErrUntrusted
	}
	return s.protected(name, tree, key, true)
}

func (s Store) childProductFile(name string, raw []byte) error {
	fd, err := unix.Open(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return ErrUntrusted
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return ErrUntrusted
	}
	if unix.Fchown(fd, int(s.MappedUID), -1) != nil || unix.Fchmod(fd, 0400) != nil || f.Sync() != nil {
		f.Close()
		return ErrUntrusted
	}
	return f.Close()
}
