package physicalgate

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type originalAdmissionAuthority struct {
	sourceAccessAuthority
	checked bool
}

func (a *originalAdmissionAuthority) VerifyAdmissionOriginals(context.Context, Caller, string, state.PhysicalPermit) error {
	a.checked = true
	return ErrPrerequisite
}

// Actual Unix -> owner check -> SAME SQLite boundary, with explicitly detached
// process/authority supplier. No provider/native process or manager helper.
func TestAdmissionOriginalFailureDeniesACKAndOwnerCommit(t *testing.T) {
	ctx := context.Background()
	root, err := os.MkdirTemp("", "g-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained detached SOURCE socket/SQLite", root)
	s, err := state.Open(filepath.Join(root, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	case_ := state.PhysicalCase{TaskID: "task", ServerID: "server", CaseDigest: model.WorkspaceDigest("case"), BaselineDigest: model.WorkspaceDigest("baseline"), Requests: 2, Preparations: 1, AccessRequests: 1, ModelRequests: 1, UsdMicros: 842000}
	if err = s.AdoptPhysicalLedger(ctx, case_, nil); err != nil {
		t.Fatal(err)
	}
	e := AccessEnrollment{Caller: Caller{SandboxID: "box", SandboxGeneration: 1, NativeInstance: "runtime-access", NativeIdentityDigest: model.WorkspaceDigest("detached process")}, Case: case_}
	authority := &originalAdmissionAuthority{sourceAccessAuthority: sourceAccessAuthority{registry: &AccessRegistry{Store: s}, enrollment: e}}
	socket := filepath.Join(root, "gate.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go (Server{Store: s, Authority: authority}).Serve(l)
	request := model.PhysicalAdmitRequest{Consumer: "access", PreparationID: "prep", RequestIndex: 1, OuterPhysicalIndex: 1, AuthorityDigest: model.WorkspaceDigest("authority"), RequestDigest: model.WorkspaceDigest("not original")}
	body, _ := json.Marshal(request)
	reply, err := Call(ctx, socket, model.PhysicalRPCRequest{FormatVersion: 1, Action: "admit", OperationID: "operation", Body: body})
	if err != nil || reply.Status != "refused" || !authority.checked {
		t.Fatal("original failure did not deny actual ACK", reply, err)
	}
	cut, err := s.PhysicalLedgerCut(ctx)
	if err != nil || cut.Owner != nil || cut.Cumulative.PhysicalRequests != 0 {
		t.Fatal("refused original acquired physical ownership", err)
	}
}

func TestAccessAdmissionOriginalIsCredentialedGETNotContext(t *testing.T) {
	input := model.QualificationAccessContext{FormatVersion: 1}
	input.Request.Method, input.Request.URL = "GET", accessURL
	r, err := http.NewRequest(http.MethodGet, accessURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Close = true
	r.Header.Set("Authorization", "Bearer explicitly-synthetic")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("User-Agent", "warpmetal-runtime-access")
	var wire bytes.Buffer
	if err = r.Write(&wire); err != nil {
		t.Fatal(err)
	}
	if err = verifyAccessRequestOriginal(wire.Bytes(), input); err != nil {
		t.Fatal("constructed original refused", err)
	}
	r.Header.Del("Authorization")
	wire.Reset()
	_ = r.Write(&wire)
	if err = verifyAccessRequestOriginal(wire.Bytes(), input); err == nil {
		t.Fatal("context proved absent credentialed GET")
	}
}
