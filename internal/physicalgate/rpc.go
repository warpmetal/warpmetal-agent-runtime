// Package physicalgate owns the closed private reverse RPC, not model execution.
package physicalgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const HostDirectory = "/run/warpmetal/physical-gate"
const HostSocket = HostDirectory + "/rpc.sock"
const ContainerDirectory = "/warpmetal-physical-gate"
const ContainerSocket = ContainerDirectory + "/rpc.sock"

var ErrPrerequisite = errors.New("physical gate verified prerequisite absent")

type Peer struct {
	PID      int
	UID, GID uint32
}
type Caller struct {
	SandboxID                            string
	SandboxGeneration                    int64
	NativeInstance, NativeIdentityDigest string
}

func (c Caller) Subject() state.PhysicalSubject {
	return state.PhysicalSubject{SandboxID: c.SandboxID, SandboxGeneration: c.SandboxGeneration, NativeInstance: c.NativeInstance, NativeIdentityDigest: c.NativeIdentityDigest}
}

type Authority interface {
	Authenticate(context.Context, Peer) (Caller, error)
	AuthorizeAdmission(context.Context, Caller, model.PhysicalAdmitRequest) (state.PhysicalPermit, error)
	VerifySettlement(context.Context, Caller, state.PhysicalOperation, model.PhysicalSettlement) error
}
type Server struct {
	Store     *state.Store
	Authority Authority
}

func (s Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}
func (s Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Authenticate before reading anything selected by the client. Kernel identity
	// is queried from the actual socket (including test transport wrappers).
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok || s.Store == nil || s.Authority == nil {
		return
	}
	peer, err := socketPeer(sc)
	if err != nil {
		return
	}
	caller, err := s.Authority.Authenticate(ctx, peer)
	if err != nil {
		return
	}
	check := func() error { return nil }
	if owner, ok := s.Authority.(interface {
		HoldPeer(context.Context, Peer, Caller) (func() error, func(), error)
	}); ok {
		verify, close, err := owner.HoldPeer(ctx, peer, caller)
		if err != nil {
			return
		}
		defer close()
		check = verify
	}
	raw, err := readFrame(c)
	if err != nil {
		return
	}
	r, err := model.DecodePhysicalRequest(raw)
	if err != nil {
		return
	}
	status := "refused"
	code := "authority_or_history_refused"
	reply := model.PhysicalRPCResponse{FormatVersion: 1, OperationID: r.OperationID, Status: status, Error: &code}
	switch r.Action {
	case "admit":
		var b model.PhysicalAdmitRequest
		_ = json.Unmarshal(r.Body, &b)
		permit, e := s.Authority.AuthorizeAdmission(ctx, caller, b)
		if e == nil && permit.Case.AccountingVersion == 2 && permit.Provider == nil {
			e = ErrPrerequisite
		}
		if e == nil {
			if owner, ok := s.Authority.(interface {
				VerifyAdmissionOriginals(context.Context, Caller, string, state.PhysicalPermit) error
			}); ok {
				e = owner.VerifyAdmissionOriginals(ctx, caller, r.OperationID, permit)
			}
		}
		// Hold/recheck the process identity through independently verified authority
		// and commit. Lost ACK leaves unknown ownership; no rollback/refund/retry.
		if e == nil && permit.Caller == caller.Subject() && reflect.DeepEqual(permit.Request, b) {
			current, e := s.Authority.Authenticate(ctx, peer)
			if e == nil && current == caller && check() == nil && s.Store.AdmitPhysical(ctx, r.OperationID, permit) == nil && check() == nil && ctx.Err() == nil {
				reply.Status = "admitted"
				reply.Error = nil
			}
		}
	case "settle", "status":
		o, e := s.Store.PhysicalOperation(ctx, r.OperationID)
		if e == nil && o == nil && r.Action == "status" {
			reply.Status = "absent"
			reply.Error = nil
		}
		if e == nil && o != nil && o.Permit.Caller == caller.Subject() {
			if r.Action == "status" {
				reply.Status = o.Phase
				reply.Error = nil
			} else {
				var b model.PhysicalSettlement
				_ = json.Unmarshal(r.Body, &b)
				current, authenticated := s.Authority.Authenticate(ctx, peer)
				if authenticated == nil && current == caller && check() == nil && s.Authority.VerifySettlement(ctx, caller, *o, b) == nil && check() == nil && s.Store.SettlePhysical(ctx, r.OperationID, caller.Subject(), b) == nil {
					reply.Status = "settled"
					reply.Error = nil
				}
			}
		}
	}
	if check() != nil || ctx.Err() != nil {
		return
	}
	out, _ := json.Marshal(reply)
	_, _ = c.Write(append(out, '\n'))
}
func readFrame(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, model.PhysicalWireMaximum+1))
	if err != nil || len(raw) > model.PhysicalWireMaximum || len(raw) < 2 || raw[len(raw)-1] != '\n' || bytes.Contains(raw[:len(raw)-1], []byte{'\n'}) {
		return nil, model.ErrPhysicalWire
	}
	return raw[:len(raw)-1], nil
}
func Call(ctx context.Context, socket string, r model.PhysicalRPCRequest) (model.PhysicalRPCResponse, error) {
	var result model.PhysicalRPCResponse
	raw, err := json.Marshal(r)
	if err != nil {
		return result, err
	}
	if _, err = model.DecodePhysicalRequest(raw); err != nil {
		return result, err
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return result, err
	}
	defer c.Close()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	done := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer done()
	if _, err = c.Write(append(raw, '\n')); err != nil {
		return result, err
	}
	if err = c.(*net.UnixConn).CloseWrite(); err != nil {
		return result, err
	}
	raw, err = readFrame(c)
	if err != nil {
		return result, err
	}
	if model.DecodePhysicalClosed(raw, &result) != nil || result.FormatVersion != 1 || result.OperationID != r.OperationID {
		return result, model.ErrPhysicalWire
	}
	switch result.Status {
	case "admitted":
		if r.Action != "admit" || result.Error != nil {
			return result, model.ErrPhysicalWire
		}
	case "local-terminal":
		// Readback only. Local completion releases concurrency, not paid usage;
		// it can never acknowledge an admit or settle operation.
		if r.Action != "status" || result.Error != nil {
			return result, model.ErrPhysicalWire
		}
	case "settled", "unknown", "absent", "refused":
	default:
		return result, model.ErrPhysicalWire
	}
	return result, nil
}
