package physicalgate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type sourceAccessTransport struct {
	local       *url.URL
	unknown     bool
	expectedURL string
}

func (t sourceAccessTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.unknown {
		return nil, errors.New("explicit synthetic completion unknown")
	}
	expected := t.expectedURL
	if expected == "" {
		expected = "https://api.openai.com/v1/models/gpt-4.1-mini-2025-04-14"
	}
	if r.URL.String() != expected || r.Method != "GET" {
		return nil, errors.New("access changed original selector")
	}
	x := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.local.Scheme
	u.Host = t.local.Host
	x.URL = &u
	x.Host = t.local.Host
	response, err := http.DefaultTransport.RoundTrip(x)
	if response != nil {
		response.Request = r
	}
	return response, err
}

type sourceAccessAuthority struct {
	registry   *AccessRegistry
	enrollment AccessEnrollment
}

func (a sourceAccessAuthority) Authenticate(context.Context, Peer) (Caller, error) {
	return a.enrollment.Caller, nil
}
func (a sourceAccessAuthority) AuthorizeAdmission(_ context.Context, c Caller, r model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	if c != a.enrollment.Caller || r.Consumer != "access" || r.OuterPhysicalIndex != 1 || r.RequestIndex != 1 {
		return state.PhysicalPermit{}, ErrPrerequisite
	}
	p := state.PhysicalPermit{Case: a.enrollment.Case, Caller: c.Subject(), Request: r, AllocationID: "source_access", PreparationOrdinal: 0}
	if a.enrollment.Case.AccountingVersion == 2 {
		p.Provider = &state.ProviderAdmission{}
	}
	return p, nil
}
func (a sourceAccessAuthority) VerifySettlement(ctx context.Context, c Caller, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	if err := a.registry.VerifySettlement(ctx, c, o, e); err != nil {
		return err
	}
	if o.Permit.Case.AccountingVersion == 2 {
		// This probe journey detaches financial authority. The separate existing
		// qualification HTTPS/PG journey proves the real signed backend ACK.
		return a.registry.Store.RetainPhysicalFact(ctx, "provider_settlement_ack_"+model.RawPhysicalDigest([]byte(o.OperationID))[7:], []byte(`{"sourceOnly":true}`))
	}
	return nil
}

// ONE actual local GET and real Unix/SQLite admission. Kernel/installed signed
// facts are explicit detached suppliers; no production override or provider.
func TestEnrolledAccessProbeUsesSameGateAndRetainsUnknown(t *testing.T) {
	base := os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires approved retained SOURCE evidence root")
	}
	flash := os.Getenv("WARPMETAL_ACCESS_PROVIDER_CONTEXT")
	wantedURL, wantedPath := "https://api.openai.com/v1/models/gpt-4.1-mini-2025-04-14", "/v1/models/gpt-4.1-mini-2025-04-14"
	responseBody := `{"id":"gpt-4.1-mini-2025-04-14","object":"model"}`
	var current model.QualificationAccessContext
	if flash != "" {
		raw, err := os.ReadFile(flash)
		if err != nil || model.DecodePhysicalClosed(raw, &current) != nil {
			t.Fatal("closed access2 context decoder refused", err)
		}
		// Current unsigned readback SOURCE, never a changed signed authority.
		current.ExpiresAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
		if err := current.Validate(current.QualificationID, time.Now()); err != nil {
			t.Fatal("access2 current context refused", err)
		}
		wantedURL, wantedPath = "https://api.deepseek.com/models", "/models"
		responseBody = `{"object":"list","data":[{"id":"deepseek-flash","object":"model"}]}`
	}
	root, err := os.MkdirTemp(base, "access-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SOURCE_PRIVATE_ARTIFACTS", root)
	short, err := os.MkdirTemp("/private/var/folders/ln/3pk8bkxd7f72yhhjwpwpb56m0000gn/T/opencode", "g-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SOURCE_SOCKET_ARTIFACTS", short)
	count := 0
	observationTimes := make(chan [2]time.Time, 1)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		requestObservedAt := time.Now().UTC()
		if r.Method != "GET" || r.URL.Path != wantedPath || r.Header.Get("Authorization") != "Bearer explicitly-synthetic" {
			t.Error("access physical original drift")
		}
		w.Header().Set("X-Request-Id", "req_original_local_access")
		w.Header().Set("X-Private-Not-Evidence", "synthetic-secret-response-header")
		_, _ = io.WriteString(w, responseBody)
		observationTimes <- [2]time.Time{requestObservedAt, time.Now().UTC()}
	}))
	defer local.Close()
	u, _ := url.Parse(local.URL)
	for _, unknown := range []bool{false, true} {
		name := "known"
		if unknown {
			name = "unknown"
		}
		s, err := state.Open(filepath.Join(root, name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		c := state.PhysicalCase{TaskID: "source_task", ServerID: "source_server", CaseDigest: model.WorkspaceDigest("case"), BaselineDigest: model.WorkspaceDigest("baseline"), Requests: 2, Preparations: 1, AccessRequests: 1, ModelRequests: 1, UsdMicros: 842000}
		if flash != "" {
			c.AccountingVersion = 2
			c.ProviderPolicyDigest = providerpolicy.FlashDigest
			c.UsdMicros = 3000000
		}
		if err = s.AdoptPhysicalLedger(context.Background(), c, nil); err != nil {
			t.Fatal(err)
		}
		e := AccessEnrollment{Caller: Caller{SandboxID: "source_box", SandboxGeneration: 1, NativeInstance: "runtime-access", NativeIdentityDigest: model.WorkspaceDigest("synthetic_process")}, Case: c, Context: model.QualificationAccessContext{PreparationID: "source_preparation", AuthorityDigest: model.WorkspaceDigest("authority"), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}}
		e.Context.Request.Method = "GET"
		e.Context.FormatVersion = 1
		e.Context.Request.URL = "https://api.openai.com/v1/models/gpt-4.1-mini-2025-04-14"
		e.Context.Allocation = []byte(`{"firstPhysicalIndex":1}`)
		if flash != "" {
			e.Context = current
		}
		e.AuthorizedUntil = time.Now().Add(time.Minute)
		if flash != "" {
			raw, _ := json.Marshal(e)
			if err := s.RetainPhysicalFact(context.Background(), "access_"+e.Context.PreparationID, raw); err != nil {
				t.Fatal(err)
			}
		}
		registry := &AccessRegistry{Store: s}
		socket := filepath.Join(short, name+".sock")
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetUnlinkOnClose(false)
		go (Server{Store: s, Authority: sourceAccessAuthority{registry: registry, enrollment: e}}).Serve(l)
		result, err := registry.runProbe(context.Background(), e, "explicitly-synthetic", socket, sourceAccessTransport{local: u, unknown: unknown, expectedURL: wantedURL})
		if (err != nil) != unknown {
			t.Fatal(name, err)
		}
		if !unknown && result.ResponseDigest == "" {
			t.Fatal("original access bytes absent")
		}
		h, err := s.PhysicalHistory(context.Background(), c)
		if err != nil || len(h) != 1 || h[0].ReservedUsdMicros != 421000 {
			t.Fatal("access prefix/reservation", err)
		}
		phase := "settled"
		if unknown {
			phase = "unknown"
		}
		if h[0].Phase != phase {
			t.Fatal("unknown access released physical owner", h[0].Phase)
		}
		original, readErr := s.PhysicalFact(context.Background(), "probe_observation_"+h[0].OperationID)
		if unknown {
			if readErr == nil && len(original) > 0 {
				t.Fatal("unknown transport invented original metadata")
			}
			if _, err = registry.ReadProbeObservation(context.Background(), h[0].OperationID); err == nil {
				t.Fatal("missing historical original accepted")
			}
		} else {
			times := <-observationTimes
			if readErr != nil {
				t.Fatal("same one-shot request omitted original safe metadata", readErr)
			}
			var observation map[string]json.RawMessage
			if json.Unmarshal(original, &observation) != nil || len(observation) != 9 {
				t.Fatal("closed access observation wire")
			}
			var providerID, start, end, operation, requestDigest, responseDigest, evidenceDigest string
			for k, v := range map[string]*string{"providerRequestId": &providerID, "startedAt": &start, "completedAt": &end, "operationId": &operation, "requestDigest": &requestDigest, "responseDigest": &responseDigest, "evidenceDigest": &evidenceDigest} {
				if json.Unmarshal(observation[k], v) != nil {
					t.Fatal("missing original", k)
				}
			}
			started, se := time.Parse(time.RFC3339Nano, start)
			completed, ce := time.Parse(time.RFC3339Nano, end)
			if se != nil || ce != nil || started.After(times[0]) || completed.Before(times[1]) || started.After(completed) || providerID != "req_original_local_access" || operation != result.OperationID || requestDigest != result.RequestDigest || responseDigest != result.ResponseDigest || evidenceDigest != result.Settlement.EvidenceDigest {
				t.Fatal("actual request-time/header/digest provenance missing")
			}
			completion, e := s.PhysicalFact(context.Background(), "probe_completion_"+result.OperationID)
			var old map[string]json.RawMessage
			if e != nil || json.Unmarshal(completion, &old) != nil || len(old) != 5 || model.RawPhysicalDigest(completion) != evidenceDigest {
				t.Fatal("old five-field completion/settlement hash changed", e)
			}
			resultBytes, _ := json.Marshal(result)
			var exported map[string]json.RawMessage
			if json.Unmarshal(resultBytes, &exported) != nil || model.RawPhysicalDigest(exported["Observation"]) != model.RawPhysicalDigest(original) {
				t.Fatal("normal private result omitted/rebuilt bound original")
			}
			if strings.Contains(string(resultBytes), "synthetic-secret-response-header") {
				t.Fatal("arbitrary response headers leaked")
			}
			if flash != "" {
				originals, _, err := s.NativeProviderOriginals(context.Background(), result.OperationID, result.Settlement)
				if err != nil || len(originals.Request) != 0 || result.RequestDigest != model.RawPhysicalDigest(nil) || string(originals.Response) != responseBody || originals.ProviderRequestID != providerID {
					t.Fatal("Flash original archive/body mapping", err)
				}
				if strings.Contains(string(originals.Transport), "synthetic") || strings.Contains(string(originals.Transport), "Authorization") {
					t.Fatal("credential reached shared transport original")
				}
				var transport map[string]string
				if json.Unmarshal(originals.Transport, &transport) != nil || len(transport) != 3 || transport["url"] != wantedURL || transport["method"] != "GET" || transport["bodyDigest"] != result.RequestDigest {
					t.Fatal("fixed actual access transport original")
				}
			}
			if err = s.RetainPhysicalFact(context.Background(), "probe_observation_"+result.OperationID, append(original, ' ')); err == nil {
				t.Fatal("first observed original replaced")
			}
		}
		_, err = registry.runProbe(context.Background(), e, "explicitly-synthetic", socket, sourceAccessTransport{local: u, expectedURL: wantedURL})
		if err == nil {
			t.Fatal("access admission replay/refund")
		}
		_ = l.Close()
		_ = s.Close()
	}
	if count != 1 {
		t.Fatal("access retry/additional physical GET", count)
	}
	t.Log("SOURCE local HTTP=1, provider=0, native=0; access unknown retains singleton and421000 reservation")
}
