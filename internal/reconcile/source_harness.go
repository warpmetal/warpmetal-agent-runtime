package reconcile

import (
	"context"
	"errors"
	"os"
	"regexp"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/sourcebridge"
)

type ownedSourceHarness struct {
	peer            sourcebridge.Peer
	authorityDigest string
	serverID        string
}

type OwnedSourceContext struct {
	Owner           sourcebridge.Peer `json:"owner"`
	Harness         sourcebridge.Peer `json:"harness"`
	ServerID        string            `json:"serverId"`
	RuntimeRevision int64             `json:"runtimeRevision"`
	AuthorityDigest string            `json:"authorityDigest"`
}

var sourceAuthorityDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Explicit host harness enrollment on the already-existing Reconciler. Pins are
// supplied OUTSIDE requests by its process owner. No socket, process, key, finite
// authority, backend row, credential or physical reservation is created here.
// Enrollment fixes ONE harness/unsigned packet for this process lifetime. Restart
// cannot reset the original physical/continuation journals or authorize replay.
func (r *Reconciler) EnrollOwnedSourceHarness(ctx context.Context, peer sourcebridge.Peer, authorityDigest string) error {
	if r == nil || ctx.Err() != nil || r.Store == nil || r.ServerID == "" || r.ManagedExecutionContext == nil || r.ManagedExecutionContext.Err() != nil || peer.PID < 1 || !sourceAuthorityDigest.MatchString(authorityDigest) {
		return errors.New("SOURCE owning process enrollment absent")
	}
	current := r.currentAuthorityManifest()
	if current.ServerID != r.ServerID || current.DesiredRevision < 1 {
		return errors.New("SOURCE normal Runtime authority absent")
	}
	r.sourceHarnessMu.Lock()
	defer r.sourceHarnessMu.Unlock()
	if r.sourceHarness != nil {
		if r.sourceHarness.peer != peer || r.sourceHarness.authorityDigest != authorityDigest || r.sourceHarness.serverID != r.ServerID {
			return errors.New("SOURCE original enrollment cannot be replaced")
		}
		return nil
	}
	r.sourceHarness = &ownedSourceHarness{peer: peer, authorityDigest: authorityDigest, serverID: r.ServerID}
	return nil
}

// Normal process/context provider: current validated authority plus actual kernel
// process identity. It does not claim native Sandbox ancestry or supplier ready.
func (r *Reconciler) OwnedSourceRuntimeContext(ctx context.Context) (OwnedSourceContext, error) {
	var empty OwnedSourceContext
	if r == nil || ctx.Err() != nil || r.Store == nil || r.ManagedExecutionContext == nil || r.ManagedExecutionContext.Err() != nil {
		return empty, errors.New("SOURCE Runtime lifecycle unavailable")
	}
	r.sourceHarnessMu.Lock()
	defer r.sourceHarnessMu.Unlock()
	current := r.currentAuthorityManifest()
	if r.sourceHarness == nil || current.ServerID != r.sourceHarness.serverID || current.ServerID != r.ServerID || current.DesiredRevision < 1 {
		return empty, errors.New("SOURCE original harness/current context absent")
	}
	return OwnedSourceContext{Owner: sourcebridge.Peer{PID: os.Getpid(), UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, Harness: r.sourceHarness.peer, ServerID: r.ServerID, RuntimeRevision: current.DesiredRevision, AuthorityDigest: r.sourceHarness.authorityDigest}, nil
}
