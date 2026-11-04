package qualification_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Fixed node TLS GET -> signed Store -> native loader/hooks -> real local HTTP
// and file/SQLite reads. Only keys/installed/qualification/native identity are
// synthetic SOURCE suppliers. Not authority2 SOURCE10 or selected LIVE26.
func TestChildProductSignedStoreToNativeBoundary(t *testing.T) {
	base := os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires retained SOURCE evidence directory, no native/fixture fallback")
	}
	root, err := os.MkdirTemp(base, "signed-product-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	packet := filepath.Join(root, "fixture.json")
	args := []string{"-B", "testdata/child_product_boundary_fixture.py", "../workflowcontract/schema", filepath.Join(base, "exact-schema-output-fixture-r2.json"), packet}
	if os.Getenv("WARPMETAL_PRODUCT_PROVIDER_BOUNDARY") == "1" {
		args = append(args, "--flash-provider-boundary")
	}
	if os.Getenv("WARPMETAL_CHILD_RESULT_BOUNDARY") == "1" {
		args = append(args, "--coding-result-boundary")
	}
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_BOUNDARY") == "1" {
		args = append(args, "--integration-result-boundary")
	}
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_DELIVERY_BOUNDARY") == "1" {
		args = append(args, "--integration-delivery-boundary")
	}
	if os.Getenv("WARPMETAL_CHILD_APPROVED_SOURCE_BOUNDARY") == "1" {
		args = append(args, "--approved-source-reference-boundary")
	}
	if os.Getenv("WARPMETAL_CHILD_WORKER_SOURCE_BOUNDARY") == "1" {
		args = append(args, "--worker-source-read-boundary")
	}
	if os.Getenv("WARPMETAL_CHILD_REVIEWER_DELIVERY_BOUNDARY") == "1" {
		args = append(args, "--reviewer-delivery-boundary")
	}
	command := exec.Command("python3", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("SOURCE supplier: %v\n%s", err, output)
	}
	var fixture struct {
		AuthoritySynthetic   bool                              `json:"authoritySynthetic"`
		LiveAuthorized       bool                              `json:"liveAuthorized"`
		Prepare              json.RawMessage                   `json:"prepare"`
		Execute              json.RawMessage                   `json:"execute"`
		Witness              qualification.ChildProductWitness `json:"witness"`
		PrepareEntry         model.CellServiceV3               `json:"prepareEntry"`
		OperatorPEM          []byte                            `json:"operatorPEM"`
		IntegrationOriginals struct {
			TargetDetail json.RawMessage `json:"targetDetail"`
			TargetBase64 []byte          `json:"targetBase64"`
			Artifact     json.RawMessage `json:"artifact"`
		} `json:"integrationOriginals"`
		IntegrationInstalledFacts struct {
			Prepare qualification.ChildProductInstalledFacts `json:"prepare"`
			Execute qualification.ChildProductInstalledFacts `json:"execute"`
		} `json:"integrationInstalledFacts"`
		ReviewerOriginals struct {
			TargetDetail    json.RawMessage `json:"targetDetail"`
			TargetBase64    []byte          `json:"targetBase64"`
			CandidateBase64 []byte          `json:"candidateBase64"`
			PacketBase64    []byte          `json:"packetBase64"`
		} `json:"reviewerOriginals"`
		ReviewerInstalledFacts struct {
			Prepare qualification.ChildProductInstalledFacts `json:"prepare"`
			Execute qualification.ChildProductInstalledFacts `json:"execute"`
		} `json:"reviewerInstalledFacts"`
	}
	raw, err := os.ReadFile(packet)
	if err != nil || json.Unmarshal(raw, &fixture) != nil || !fixture.AuthoritySynthetic || fixture.LiveAuthorized {
		t.Fatal("SOURCE supplier authority refused")
	}
	w := fixture.Witness
	var prepareInstalled *qualification.ChildInstalledInputs
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_DELIVERY_BOUNDARY") == "1" {
		pre, post := qualification.SourceIntegrationInstalledForTest(t, w, fixture.PrepareEntry, fixture.IntegrationInstalledFacts.Prepare, fixture.IntegrationInstalledFacts.Execute)
		prepareInstalled = &pre
		w.InstalledInputs = &post
	}
	if os.Getenv("WARPMETAL_CHILD_REVIEWER_DELIVERY_BOUNDARY") == "1" {
		pre, post := qualification.SourceReviewerInstalledForTest(t, w, fixture.PrepareEntry, fixture.ReviewerInstalledFacts.Prepare, fixture.ReviewerInstalledFacts.Execute)
		prepareInstalled = &pre
		w.InstalledInputs = &post
	}
	prepareWitness := w
	if prepareInstalled != nil {
		prepareWitness.InstalledInputs = prepareInstalled
	}
	prepareWitness.Entry = fixture.PrepareEntry
	prepareWitness.ActualReceipt = nil
	prepareWitness.Grant = nil
	prepareWitness.Authorization = nil
	prepareWitness.AcceptedPreparationEnvelope = nil
	prepareWitness.AcceptedDemandEnvelope = nil
	store := qualification.SourceBoundaryStoreForTest(filepath.Join(root, "store"), uint32(os.Getuid()))
	tree, key, err := store.Paths(w.Applicability.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(key), filepath.Join(tree, "preparations")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(key, fixture.OperatorPEM, 0400); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{tree, filepath.Join(tree, "preparations")} {
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "darwin" {
		// Only this scoped temporary SOURCE tree; no sudo/production volume.
		owner, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		ace := "user:" + owner.Username + " allow add_file,add_subdirectory,delete_child,directory_inherit"
		for _, dir := range []string{tree, filepath.Join(tree, "preparations")} {
			if out, err := exec.Command("chmod", "+a", ace, dir).CombinedOutput(); err != nil {
				t.Fatalf("SOURCE writer ACL: %v %s", err, out)
			}
		}
	}
	box := model.Sandbox{ID: w.Applicability.SandboxID, Generation: w.Applicability.SandboxGeneration, Cell: true}
	calls := 0
	targetCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if os.Getenv("WARPMETAL_CHILD_REVIEWER_DELIVERY_BOUNDARY") == "1" && r.Header.Get("X-WarpMetal-Workflow-Lease") == "wfl_source_reviewer" {
			targetCalls++
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.URL.RawQuery != "" || r.ContentLength > 0 {
				t.Error("SOURCE reviewer target transport changed")
				rw.WriteHeader(403)
				return
			}
			switch r.URL.Path {
			case "/internal/runtime/workspace-workflow/results/synthetic_result":
				rw.Header().Set("Content-Type", "application/json")
				_, _ = rw.Write(fixture.ReviewerOriginals.TargetDetail)
			case "/internal/runtime/workspace-workflow/executions/source_execution/artifacts/source_target_artifact":
				rw.Header().Set("Content-Type", "text/plain")
				rw.Header().Set("X-Content-Digest", qualification.Digest(fixture.ReviewerOriginals.TargetBase64))
				_, _ = rw.Write(fixture.ReviewerOriginals.TargetBase64)
			default:
				t.Error("unexpected SOURCE reviewer target fetch")
				rw.WriteHeader(403)
			}
			return
		}
		if os.Getenv("WARPMETAL_CHILD_INTEGRATION_DELIVERY_BOUNDARY") == "1" && r.Header.Get("X-WarpMetal-Workflow-Lease") == "wfl_source_manager" {
			targetCalls++
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.URL.RawQuery != "" || r.ContentLength > 0 {
				t.Error("SOURCE manager target transport changed")
				rw.WriteHeader(403)
				return
			}
			switch r.URL.Path {
			case "/internal/runtime/workspace-workflow/results/synthetic_result":
				rw.Header().Set("Content-Type", "application/json")
				_, _ = rw.Write(fixture.IntegrationOriginals.TargetDetail)
			case "/internal/runtime/workspace-workflow/executions/source_execution/artifacts/source_target_artifact":
				rw.Header().Set("Content-Type", "text/plain")
				rw.Header().Set("X-Content-Digest", qualification.Digest(fixture.IntegrationOriginals.TargetBase64))
				_, _ = rw.Write(fixture.IntegrationOriginals.TargetBase64)
			default:
				t.Error("unexpected SOURCE target fetch")
				rw.WriteHeader(403)
			}
			return
		}
		calls++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" || r.URL.Path != "/internal/runtime/workspace-workflow/child-preparations/"+w.Preparation.PreparationID+"/product-control" || r.URL.RawQuery != "" || r.ContentLength > 0 {
			t.Error("fixed node-only SOURCE delivery drift")
			rw.WriteHeader(403)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = rw.Write(fixture.Prepare)
		} else if calls == 2 {
			_, _ = rw.Write(fixture.Execute)
		} else {
			t.Error("unexpected dispatch/retry")
			rw.WriteHeader(409)
		}
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "synthetic-node", HTTP: server.Client()}
	prepare, err := client.ChildProductControl(context.Background(), w.Preparation.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdoptChildProduct(box, prepare, prepareWitness, time.Now()); err != nil {
		t.Fatal("positive signed Store prepare failed", err)
	}
	execute, err := client.ChildProductControl(context.Background(), w.Preparation.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("WARPMETAL_CHILD_REVIEWER_DELIVERY_BOUNDARY") == "1" {
		q, err := store.ChildProductSourceReadPolicy(box, execute, w, time.Now())
		if err != nil || q.FormatVersion != 4 || len(q.ArtifactReads) != 1 {
			t.Fatal("signed reviewer4 read-only selection", err)
		}
		if err = store.AdoptChildProduct(box, execute, w, time.Now()); err == nil {
			t.Fatal("reviewer without own physical/artifact custody admitted")
		}
		var target struct {
			Target   json.RawMessage `json:"target"`
			Artifact json.RawMessage `json:"artifact"`
		}
		if json.Unmarshal(q.ArtifactReads[0], &target) != nil {
			t.Fatal("target authority")
		}
		var control qualification.ChildProductControl
		if json.Unmarshal(execute.Bytes(), &control) != nil {
			t.Fatal("SOURCE reviewer control framing")
		}
		sourceKey := integrationSourceKey(t, root)
		detail, artifact, artifactRead := qualification.SourceReviewerCustodyForTest(t, root, w, control, fixture.ReviewerOriginals.CandidateBase64,
			func(ctx context.Context, pin, ref json.RawMessage, execution string) (json.RawMessage, []byte, error) {
				detail, err := client.ReadWorkflowResult(ctx, pin, "wfl_source_reviewer")
				if err != nil {
					return nil, nil, err
				}
				body, err := client.FetchWorkflowArtifact(ctx, execution, ref, "wfl_source_reviewer")
				return detail, body, err
			}, func() int { return targetCalls }, func(observation json.RawMessage, read func(model.WorkflowCaptureOperation) string) qualification.ChildSourceReadOriginal {
				return integrationSourceObservation(t, root, w, control, sourceKey, "reviewer_target", observation, read)
			}, integrationSourceVerifier(sourceKey))
		physicalReads := qualification.SourceReviewerInputsForTest(t, root, w, q, detail, artifact, fixture.ReviewerOriginals.CandidateBase64, fixture.ReviewerOriginals.PacketBase64, func(label string, observation json.RawMessage, read func(model.WorkflowCaptureOperation) string) qualification.ChildSourceReadOriginal {
			return integrationSourceObservation(t, root, w, control, sourceKey, label, observation, read)
		})
		qualification.SourceReviewerOwnFieldsForTest(t, w, fixture.ReviewerInstalledFacts.Execute, execute.GenerationDigest(), q.ArtifactReads[0], artifact)
		qualification.SourceReviewerPreparedForTest(t, root, store, box, execute, w)
		if os.Getenv("WARPMETAL_REVIEWER_DELIVERY_ACK_BOUNDARY") == "1" {
			// Explicit SOURCE producer/ACK suppliers exercise the final typed
			// boundary; protected lifecycle assembly is a separate installed gate.
			w.ReviewReads = physicalReads
			w.ArtifactReviewReads = []model.ArtifactReviewReadWitness{artifactRead}
			if err = store.AdoptChildProduct(box, execute, w, time.Now()); err != nil {
				t.Fatal("current signed delivery2 with own SOURCE physical/artifact first ACKs refused", err)
			}
			if _, err = store.ReadChildProduct(box, w.Preparation.PreparationID, w, time.Now()); err != nil {
				t.Fatal("delivery2 current SOURCE readback", err)
			}
			changed := w
			changed.ArtifactReviewReads = append([]model.ArtifactReviewReadWitness(nil), w.ArtifactReviewReads...)
			changed.ArtifactReviewReads[0].Bytes = []byte("changed cached original")
			if err = store.AdoptChildProduct(box, execute, changed, time.Now()); err == nil {
				t.Fatal("changed immutable artifact witness admitted")
			}
		}
		if os.Getenv("WARPMETAL_REVIEWER_TERMINAL_BOUNDARY") == "1" {
			if os.Getenv("WARPMETAL_REVIEWER_DELIVERY_ACK_BOUNDARY") != "1" {
				t.Fatal("terminal requires first SOURCE Store adoption")
			}
			qualification.SourceReviewerCompletedForTest(t, root, w, control)
		}
		if os.Getenv("WARPMETAL_REVIEWER_ACK_REOPEN_BOUNDARY") == "1" {
			if os.Getenv("WARPMETAL_REVIEWER_DELIVERY_ACK_BOUNDARY") != "1" {
				t.Fatal("reopen requires first SOURCE Store adoption")
			}
			qualification.SourceReviewerACKReopenForTest(t, root, store, box, execute, w, integrationSourceVerifier(sourceKey))
		}
		if os.Getenv("WARPMETAL_REVIEWER_SANDBOX_BOUNDARY") == "1" {
			if os.Getenv("WARPMETAL_REVIEWER_DELIVERY_ACK_BOUNDARY") != "1" {
				t.Fatal("reviewer native SOURCE requires strict Store first")
			}
			bundle := qualification.SourceReviewerCustodyBundleForTest(t, root, w, control)
			if os.WriteFile(filepath.Join(root, "source-reviewer-custody.json"), bundle, 0400) != nil {
				t.Fatal("SOURCE detached bundle")
			}
			native := os.Getenv("WARPMETAL_PRODUCT_SOURCE_NATIVE_SCRIPT")
			output, err := exec.Command("node", native, tree, key, packet, root, strconv.Itoa(os.Getuid())).CombinedOutput()
			if os.WriteFile(filepath.Join(root, "reviewer-native-boundary.txt"), output, 0600) != nil {
				t.Fatal("SOURCE native output retention")
			}
			if err != nil {
				t.Fatalf("reviewer signed native SOURCE boundary: %v\n%s", err, output)
			}
			t.Log(string(output))
		}
		if os.Getenv("WARPMETAL_REVIEWER_DELIVERY_ACK_BOUNDARY") == "1" {
			t.Log("reviewer SOURCE private read and typed Store adoption; protected lifecycle assembly, identity enrollment and native admission remain unproven")
		} else {
			t.Log("reviewer SOURCE private read; strict Store adoption and protected/native proof remain unproven")
		}
		return
	}
	if err := store.AdoptChildProduct(box, execute, w, time.Now()); err != nil {
		t.Fatal("positive signed Store execute failed", err)
	}
	if err := store.AdoptChildProduct(box, execute, w, time.Now()); err != nil {
		t.Fatal("Store exact replay failed", err)
	}
	selected, err := store.ReadChildProduct(box, execute.PreparationID(), w, time.Now())
	if err != nil || selected.Generation.Phase != "execute" || calls != 2 {
		t.Fatal("Store current readback failed", err)
	}
	if q := selected.Generation.Policy.Payload; q.FormatVersion == 1 || q.Purpose != "coding_worker" {
		if _, err := selected.ApprovedWorkerSourceReads(); !errors.Is(err, qualification.ErrWorkerSourceNotApplicable) {
			t.Fatal("verified legacy/non-coding control lost its distinct not-applicable result", err)
		}
	}
	if os.Getenv("WARPMETAL_CHILD_WORKER_SOURCE_BOUNDARY") == "1" {
		qualification.SourceWorkerReadJourneyForTest(t, root, w, selected)
	}
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_DELIVERY_BOUNDARY") == "1" {
		target, err := selected.IntegrationTarget()
		if err != nil {
			t.Fatal(err)
		}
		detail, err := client.ReadWorkflowResult(context.Background(), target.Target, "wfl_source_manager")
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := client.FetchWorkflowArtifact(context.Background(), "source_execution", target.Artifact, "wfl_source_manager")
		if err != nil || targetCalls != 2 {
			t.Fatal("manager target originals unavailable", err)
		}
		qualification.SourceIntegrationStageForTest(t, root, w, selected, detail, artifact)
		if os.Getenv("WARPMETAL_CHILD_INTEGRATION_OBSERVATION_BOUNDARY") == "1" {
			prepareSourceIntegrationObservationCustody(t, root, tree, w, selected)
		}
	}
	if os.Getenv("WARPMETAL_CHILD_APPROVED_SOURCE_BOUNDARY") == "1" {
		refs, err := selected.ApprovedSourceReferences()
		if err != nil || len(selected.Generation.Policy.Payload.SourceReads) != 2 || len(refs) != 1 {
			t.Fatal("current signed source references were not projected/deduplicated", err)
		}
		var grant struct {
			Reference model.ControllerPlanReference `json:"reference"`
		}
		if json.Unmarshal(selected.Generation.Policy.Payload.SourceReads[0].Grant, &grant) != nil || refs[0] != grant.Reference {
			t.Fatal("outcome source reference was not from the current signed grant")
		}
		outcome := qualification.ChildWorkflowNativeCapture{ApprovedSourceReferences: refs}
		if len(outcome.ApprovedSourceReferences) != 1 || len(w.ReviewReads) != 0 {
			t.Fatal("reference projection manufactured read credit")
		}
	}
	native := os.Getenv("WARPMETAL_PRODUCT_SOURCE_NATIVE_SCRIPT")
	if native == "" {
		t.Fatal("missing fixed SOURCE native boundary driver")
	}
	command = exec.Command("node", native, tree, key, packet, root, strconv.Itoa(os.Getuid()))
	output, err = command.CombinedOutput()
	if write := os.WriteFile(filepath.Join(root, "native-boundary.txt"), output, 0600); write != nil {
		t.Fatal(write)
	}
	if err != nil {
		t.Fatalf("joined native SOURCE boundary: %v\n%s", err, output)
	}
	t.Log("physical local node TLS GETs", calls, string(output))
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_DELIVERY_BOUNDARY") == "1" {
		if os.Getenv("WARPMETAL_CHILD_INTEGRATION_OBSERVATION_BOUNDARY") == "1" {
			t.Run("terminal_integration_observation", func(t *testing.T) {
				testSourceIntegrationObservationBoundary(t, root, w, selected)
			})
		}
		if os.Getenv("WARPMETAL_CHILD_INTEGRATION_OBSERVATION_BOUNDARY") != "1" {
			t.Log("successor input-only SOURCE gate: absent protected custody denied before HTTP; no completed integration capture is asserted")
		}
		return
	}
	if os.Getenv("WARPMETAL_CHILD_INTEGRATION_BOUNDARY") == "1" {
		t.Run("original_integration_before_and_after_capture", func(t *testing.T) {
			testSourceChildIntegrationCapture(t, root, w, selected, store)
		})
	}
	if os.Getenv("WARPMETAL_CHILD_RESULT_BOUNDARY") == "1" {
		t.Run("original_coding_result_capture", func(t *testing.T) {
			testSourceChildResultCapture(t, root, w, selected)
		})
	}
	if os.Getenv("WARPMETAL_CHILD_WORKFLOW_BOUNDARY") == "1" {
		t.Run("execution_scoped_worker_enrollment", func(t *testing.T) {
			testSourceChildWorkflowRoleEnrollment(t, w, selected)
		})
	}
}

type sourceMetadataRoundTrip func(*http.Request) (*http.Response, error)

func (f sourceMetadataRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Extension of the signed Store/native-loader journey, with zero network. The
// business/native/installed suppliers are detached; no grant or release occurs.
func TestSourceTransportNormalMetadataBoundary(t *testing.T) {
	base := os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires retained SOURCE evidence directory")
	}
	root, err := os.MkdirTemp(base, "source-normal-metadata-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	packet := filepath.Join(root, "fixture.json")
	command := exec.Command("python3", "-B", "testdata/child_product_boundary_fixture.py", "../workflowcontract/schema", filepath.Join(base, "exact-schema-output-fixture-r2.json"), packet, "--source-transport-metadata")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("detached supplier: %v\n%s", err, output)
	}
	var fixture struct {
		SourcePrepare       json.RawMessage `json:"sourcePrepare"`
		SourceControl       json.RawMessage `json:"sourceControl"`
		SourceParentPrepare json.RawMessage `json:"sourceParentPrepare"`
		SourceAuthority     json.RawMessage `json:"sourceAuthority"`
		OperatorPEM         []byte          `json:"operatorPEM"`
		ProducerPEM         []byte          `json:"producerPEM"`
		LegacySignature     []byte          `json:"legacyDetachedEnvelopeSignature"`
	}
	raw, err := os.ReadFile(packet)
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture framing", err)
	}
	var metadata struct {
		PreparationID string `json:"preparationId"`
		Profile       struct {
			Profile    qualification.SourceTransportProfile `json:"profile"`
			Candidate  string                               `json:"candidateInventoryDigest"`
			Reference  string                               `json:"sourceTransportPermissionDigest"`
			Permission json.RawMessage                      `json:"permission"`
		} `json:"profileMetadata"`
		Applicability qualification.Applicability `json:"applicability"`
	}
	if json.Unmarshal(fixture.SourcePrepare, &metadata) != nil {
		t.Fatal("metadata")
	}
	// canonical exact-original envelope, NOT a new signature or a payload digest.
	var permission any
	if json.Unmarshal(metadata.Profile.Permission, &permission) != nil {
		t.Fatal("permission")
	}
	permissionBytes, _ := json.Marshal(permission)
	store := qualification.SourceBoundaryStoreForTest(filepath.Join(root, "store"), uint32(os.Getuid()))
	box := model.Sandbox{ID: metadata.Applicability.SandboxID, Generation: metadata.Applicability.SandboxGeneration, Cell: true}
	tree, key, err := store.Paths(box.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(key), filepath.Join(tree, "blobs"), filepath.Join(tree, "snapshots", metadata.Profile.Reference[7:])} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, raw []byte) {
		t.Helper()
		f, e := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.Write(raw)
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			t.Fatal(e, closeErr)
		}
	}
	write(key, fixture.OperatorPEM)
	write(filepath.Join(tree, "blobs", metadata.Profile.Reference[7:]), permissionBytes)
	// Legacy detached-copy files retained solely to expose the actual payload vs
	// envelope decoder mismatch rather than manufacture a missing-file failure.
	legacy := filepath.Join(tree, "snapshots", metadata.Profile.Reference[7:], "source-transport-permission")
	write(legacy+".json", permissionBytes)
	write(legacy+".sig", fixture.LegacySignature)
	for _, dir := range []string{tree, filepath.Join(tree, "blobs"), filepath.Join(tree, "snapshots"), filepath.Dir(legacy)} {
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
	}
	adopted := qualification.SourceTransportPermissionAuthority{PermissionDigest: metadata.Profile.Reference, CandidateInventoryDigest: metadata.Profile.Candidate, Profile: metadata.Profile.Profile, OperatorKeySHA256: qualification.Digest(fixture.OperatorPEM), OperatorKeyID: "source_operator"}
	if _, err = store.ReadSourceTransportPermission(box, adopted, time.Now()); err != nil {
		t.Fatalf("normal canonical SIGNED ENVELOPE reference refused: %v", err)
	}
	decoded, err := qualification.DecodeSourceTransportMetadata(fixture.SourcePrepare, "cell_session", metadata.PreparationID, "prepare")
	if err != nil {
		t.Fatal("normal prepare decoder", err)
	}
	var authority struct {
		Producer struct {
			KeyID         string `json:"keyId"`
			KeySHA256     string `json:"keySHA256"`
			NodeTokenHash string `json:"nodeTokenHash"`
		} `json:"producer"`
	}
	if json.Unmarshal(fixture.SourceAuthority, &authority) != nil {
		t.Fatal("authority")
	}
	var localCase struct {
		Payload struct {
			Scope model.ControllerOwner `json:"scope"`
		} `json:"payload"`
	}
	if json.Unmarshal(decoded.LocalCase, &localCase) != nil {
		t.Fatal("case")
	}
	w := qualification.SourceTransportMetadataWitness{Authority: fixture.SourceAuthority, OperatorPEM: fixture.OperatorPEM, ProducerPEM: fixture.ProducerPEM, Producer: qualification.ProducerConfig{KeyID: authority.Producer.KeyID, KeySHA256: "sha256:" + authority.Producer.KeySHA256, ServerID: metadata.Applicability.ServerID, NodeTokenHash: authority.Producer.NodeTokenHash}, Target: qualification.SourceTransportTarget{TargetKind: "cell_session", PreparationID: metadata.PreparationID, Phase: "prepare", TargetID: decoded.Entry.TargetID, SourceID: decoded.Entry.SourceID, RequestDigest: decoded.Entry.RequestDigest, PreparedTuple: decoded.PreparedTuple, Scope: localCase.Payload.Scope}}
	var authorityObject any
	json.Unmarshal(fixture.SourceAuthority, &authorityObject)
	w.Authority, _ = json.Marshal(authorityObject)
	// Normal node client framing with an in-memory transport: sockets/DNS/TLS
	// and backend business suppliers are explicitly NOT exercised or credited.
	calls := 0
	client := api.Client{Origin: "https://source-metadata.invalid", NodeToken: "synthetic-node", HTTP: &http.Client{Transport: sourceMetadataRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" || r.Body != nil {
			t.Fatal("node-only empty metadata GET drift")
		}
		var body []byte
		status := 200
		switch r.URL.Path {
		case "/internal/runtime/workspace-workflow/child-preparations/" + metadata.PreparationID + "/source-transport-prepare":
			body = fixture.SourcePrepare
		case "/internal/runtime/workspace-workflow/child-preparations/" + metadata.PreparationID + "/source-transport-control":
			body = fixture.SourceControl
		case "/internal/runtime/workspace-workflow/controller-preparations/source_parent_preparation/source-transport-prepare":
			body = fixture.SourceParentPrepare
		case "/internal/runtime/workspace-workflow/controller-preparations/source_parent_preparation/source-transport-control":
			status = 409
			body = []byte(`{"error":{"code":"source_local_grant_pending"}}`)
		default:
			t.Fatal("unexpected route", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})}}
	// Scope-limited temporary writer ACL, following the existing Store boundary.
	if runtime.GOOS == "darwin" {
		owner, e := user.Current()
		if e != nil {
			t.Fatal(e)
		}
		for _, dir := range []string{tree, filepath.Join(tree, "blobs")} {
			if out, e := exec.Command("chmod", "+a", "user:"+owner.Username+" allow add_file,add_subdirectory,delete_child,directory_inherit", dir).CombinedOutput(); e != nil {
				t.Fatal(e, string(out))
			}
		}
	}
	prepare, err := client.ChildSourceTransportPrepare(context.Background(), metadata.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.AdoptSourceTransportMetadata(box, prepare, w, time.Now()); err != nil {
		t.Fatal("normal prepare adoption", err)
	}
	control, err := client.ChildSourceTransportControl(context.Background(), metadata.PreparationID)
	if err != nil {
		t.Fatal(err)
	}
	w.Target.Phase = "execute"
	if err = store.AdoptSourceTransportMetadata(box, control, w, time.Now()); err != nil {
		t.Fatal("normal control adoption", err)
	}
	parent, err := client.ControllerSourceTransportPrepare(context.Background(), "source_parent_preparation")
	if err != nil {
		t.Fatal(err)
	}
	p, err := qualification.DecodeSourceTransportMetadata(parent, "controller_activity", "source_parent_preparation", "prepare")
	if err != nil {
		t.Fatal(err)
	}
	w.Target = qualification.SourceTransportTarget{TargetKind: p.TargetKind, PreparationID: p.PreparationID, Phase: p.Phase, TargetID: p.Entry.TargetID, SourceID: p.Entry.SourceID, RequestDigest: p.Entry.RequestDigest, PreparedTuple: p.PreparedTuple, Scope: localCase.Payload.Scope}
	if err = store.AdoptSourceTransportMetadata(box, parent, w, time.Now()); err != nil {
		t.Fatal("normal parent prepare adoption", err)
	}
	if _, err = client.ControllerSourceTransportControl(context.Background(), "source_parent_preparation"); err == nil {
		t.Fatal("missing local grant allowed")
	}
	// A payload hash and metadata-supplied producer trust cannot adopt authority.
	var modified map[string]any
	json.Unmarshal(prepare, &modified)
	pm := modified["profileMetadata"].(map[string]any)
	pm["sourceTransportPermissionDigest"] = model.WorkspaceDigest(pm["permission"].(map[string]any)["payload"])
	delete(modified, "basisDigest")
	modified["basisDigest"] = model.WorkspaceDigest(modified)
	bad, _ := json.Marshal(modified)
	w.Target = qualification.SourceTransportTarget{TargetKind: decoded.TargetKind, PreparationID: decoded.PreparationID, Phase: decoded.Phase, TargetID: decoded.Entry.TargetID, SourceID: decoded.Entry.SourceID, RequestDigest: decoded.Entry.RequestDigest, PreparedTuple: decoded.PreparedTuple, Scope: localCase.Payload.Scope}
	if _, err = qualification.VerifySourceTransportMetadata(bad, w, time.Now()); err == nil {
		t.Fatal("detached payload reference accepted")
	}
	untrusted := w
	untrusted.ProducerPEM = fixture.OperatorPEM
	if _, err = qualification.VerifySourceTransportMetadata(prepare, untrusted, time.Now()); err == nil {
		t.Fatal("record self-trust accepted")
	}
	loader := os.Getenv("WARPMETAL_SOURCE_METADATA_LOADER")
	if loader == "" {
		t.Fatal("missing fixed Sandbox SOURCE metadata loader")
	}
	node := exec.Command("node", "testdata/source_transport_metadata_boundary.mjs", tree, key, packet, loader)
	output, err = node.CombinedOutput()
	if err != nil {
		t.Fatalf("normal Sandbox metadata loader: %v\n%s", err, output)
	}
	t.Log("normal SOURCE metadata boundary", calls, "in-memory GETs; network/native/provider/issuance/release=0", string(output))
}
