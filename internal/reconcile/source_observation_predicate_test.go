package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// statusProbeReceiptMutation derives the authentic ba1b status receipt from the
// journey's own probe and applies one field-level mutation, so each member of
// the running-envelope conjunction can be exercised without inventing payloads.
func statusProbeReceiptMutation(mutate func(map[string]any)) func(base func(string, map[string]any) ([]byte, error)) func(string, map[string]any) ([]byte, error) {
	return func(base func(string, map[string]any) ([]byte, error)) func(string, map[string]any) ([]byte, error) {
		return func(sandboxID string, request map[string]any) ([]byte, error) {
			if request["instance"] != "ba1b" {
				return base(sandboxID, request)
			}
			payload, err := base(sandboxID, request)
			if err != nil || payload == nil {
				return payload, err
			}
			var receipt map[string]any
			if err := json.Unmarshal(payload, &receipt); err != nil {
				return nil, err
			}
			mutate(receipt)
			return json.Marshal(receipt)
		}
	}
}

// TestReconcilerRunningSourceProbeFailuresCarryValueFreePredicateCodes is the
// A48 RED/GREEN journey: a decoded schema-v1 running envelope that fails any
// stored-native-identity member must fail closed with the FIRST failed member's
// bounded stable code in the existing conjunction order, leak no value, write
// nothing, probe no later source, and preserve the same rebuilt report/409
// behavior. Pre-change every member collapses to the generic message.
func TestReconcilerRunningSourceProbeFailuresCarryValueFreePredicateCodes(t *testing.T) {
	ctx := context.Background()
	backend := loadFrozenBackendV21(t)
	ba1bSourceID := "source_ba1b_rev1_0000001"
	finishSourceID := "source_finish_rev1_00001"
	cases := []struct {
		name  string
		code  string
		leak  string
		apply func(base func(string, map[string]any) ([]byte, error)) func(string, map[string]any) ([]byte, error)
	}{
		{
			name: "exec_error", code: "exec_error", leak: "supervisor transport failed",
			apply: func(base func(string, map[string]any) ([]byte, error)) func(string, map[string]any) ([]byte, error) {
				return func(sandboxID string, request map[string]any) ([]byte, error) {
					if request["instance"] != "ba1b" {
						return base(sandboxID, request)
					}
					payload, _ := base(sandboxID, request)
					return payload, errors.New("supervisor transport failed")
				}
			},
		},
		{name: "not_ready", code: "not_ready", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["ready"] = false
		})},
		{name: "instance_mismatch", code: "instance_mismatch", leak: "foreignmember0001", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["instance"] = "foreignmember0001"
		})},
		{name: "sandbox_mismatch", code: "sandbox_mismatch", leak: "sbx_foreignmember00001", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["sandboxId"] = "sbx_foreignmember00001"
		})},
		{name: "profile_id_mismatch", code: "profile_id_mismatch", leak: "foreignprofile0001", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["profileId"] = "foreignprofile0001"
		})},
		{name: "profile_digest_mismatch", code: "profile_digest_mismatch", leak: strings.Repeat("4", 64), apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["profileDigest"] = "sha256:" + strings.Repeat("4", 64)
		})},
		{name: "profile_revision_mismatch", code: "profile_revision_mismatch", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["profileRevision"] = float64(2)
		})},
		{name: "session_mismatch", code: "session_mismatch", leak: "ses_foreignmember0001", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["sessionId"] = "ses_foreignmember0001"
		})},
		{name: "native_project_mismatch", code: "native_project_mismatch", leak: strings.Repeat("f", 40), apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["nativeProjectId"] = strings.Repeat("f", 40)
		})},
		{name: "native_location_mismatch", code: "native_location_mismatch", leak: strings.Repeat("2", 64), apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["nativeLocationDigest"] = "sha256:" + strings.Repeat("2", 64)
		})},
		{name: "instruction_revision_mismatch", code: "instruction_revision_mismatch", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["instructionRevision"] = float64(2)
		})},
		{name: "instruction_digest_mismatch", code: "instruction_digest_mismatch", leak: strings.Repeat("3", 64), apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["instructionDigest"] = "sha256:" + strings.Repeat("3", 64)
		})},
		{name: "instruction_not_applied", code: "instruction_not_applied", apply: statusProbeReceiptMutation(func(receipt map[string]any) {
			receipt["instructionApplied"] = false
		})},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			journey := newSourceObservationJourney(t)
			base := journey.statusProbe
			journey.statusProbe = test.apply(base)
			journey.reconciler = journey.newReconciler()
			before := journey.sourceObservationDurableState(t)
			beforeBa1b := journey.storedSource(t, ba1bSourceID)
			beforeFinish := journey.storedSource(t, finishSourceID)
			passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
			t.Logf("running-envelope failure %s pass error: %v", test.name, passErr)
			if passErr == nil || !strings.Contains(passErr.Error(), "observe continuity sources") {
				t.Fatalf("running-envelope failure did not fail the observation phase: %v", passErr)
			}
			if !strings.Contains(passErr.Error(), test.code) {
				t.Fatalf("first failed member %s did not surface its bounded code: %v", test.name, passErr)
			}
			if !strings.Contains(passErr.Error(), "did not prove the exact stored native identity") {
				t.Fatalf("existing bounded message structure was not preserved: %v", passErr)
			}
			if test.leak != "" && strings.Contains(passErr.Error(), test.leak) {
				t.Fatalf("predicate error leaked the failed value for %s", test.name)
			}
			if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b"}) {
				t.Fatalf("a later source was probed after the first fatal member: %v", journey.probeInstances)
			}
			after := journey.sourceObservationDurableState(t)
			if !reflect.DeepEqual(before.withoutSources(), after.withoutSources()) {
				t.Fatalf("running-envelope failure touched unrelated durable state:\nbefore %#v\nafter  %#v",
					before.withoutSources(), after.withoutSources())
			}
			if !reflect.DeepEqual(journey.storedSource(t, ba1bSourceID), beforeBa1b) {
				t.Fatal("running-envelope failure wrote the failed source row")
			}
			if !reflect.DeepEqual(journey.storedSource(t, finishSourceID), beforeFinish) {
				t.Fatal("running-envelope failure wrote a later source row")
			}
			if applied := journey.appliedRevision(t); applied != 64 {
				t.Fatalf("running-envelope failure advanced the applied revision to %d", applied)
			}
			_, payload := journey.daemonReport(t, passErr)
			verdict, _ := backend.applyReport(
				t, payload, journey.backendV21Rows(t), journey.backendV21Sources(t),
				journey.now(), frozenBackendV21CurrentTokenHash,
			)
			if verdict.Accepted || verdict.Error.Status != 409 ||
				verdict.Error.Message != "Registration is no longer current and admissible." {
				t.Fatalf("running-envelope failure changed the rebuilt report refusal: %#v", verdict)
			}
		})
	}
}

// TestReconcilerGenuineNonRunningSourceContinuesAndPersistsOnce is the A48
// companion: a closed non-running answer is still persisted unavailable exactly
// once and does not stop the later eligible source from being observed.
func TestReconcilerGenuineNonRunningSourceContinuesAndPersistsOnce(t *testing.T) {
	ctx := context.Background()
	journey := newSourceObservationJourney(t)
	base := journey.statusProbe
	journey.statusProbe = func(sandboxID string, request map[string]any) ([]byte, error) {
		if request["instance"] == "ba1b" {
			return stoppedSourceStatusReceipt("service_stopped"), nil
		}
		return base(sandboxID, request)
	}
	journey.reconciler = journey.newReconciler()
	passErr := journey.reconciler.Reconcile(ctx, journey.manifest)
	if passErr == nil || !strings.Contains(passErr.Error(), "apply managed services:") {
		t.Fatalf("genuine non-running answer did not continue into the ordinary pass: %v", passErr)
	}
	if !reflect.DeepEqual(journey.probeInstances, []string{"ba1b", "finish"}) {
		t.Fatalf("genuine non-running answer stopped the later source: %v", journey.probeInstances)
	}
	ba1b := journey.storedSource(t, "source_ba1b_rev1_0000001")
	if ba1b.Report.Availability != "unavailable" || ba1b.Report.Reason == nil ||
		*ba1b.Report.Reason != "service_stopped" || !ba1b.Report.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("genuine non-running answer was not persisted once: %#v", ba1b.Report)
	}
	finish := journey.storedSource(t, "source_finish_rev1_00001")
	if finish.Report.Availability != "available" || !finish.Report.LastObservedAt.Equal(journey.now()) {
		t.Fatalf("later source was not observed after the non-running answer: %#v", finish.Report)
	}
}

// TestRunningReceiptFailureCodeIdentifiesTheFirstFailedMember pins the
// value-free predicate code for every member and, critically, for shapes where
// several members fail: the FIRST member in the exact evaluation order wins.
func TestRunningReceiptFailureCodeIdentifiesTheFirstFailedMember(t *testing.T) {
	source := state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{
		SandboxID: "sbx_managedservice00000001", NativeSessionID: "ses_ba1b_rev1_0000001",
		NativeProjectID:      "0123456789abcdef0123456789abcdef01234567",
		NativeLocationDigest: "sha256:" + strings.Repeat("a", 64),
	}}
	service := state.LocalManagedService{Manifest: model.ManagedServiceV1{
		Identity: model.ManagedServiceIdentityV1{Instance: "ba1b"},
		Profile: model.ManagedServiceProfileV1{
			ProfileID: "opencode", ProfileDigest: "sha256:" + strings.Repeat("b", 64), ProfileRevision: 1,
		},
		Instructions: model.ManagedServiceInstructionsV1{
			InstructionRevision: 1, InstructionDigest: "sha256:" + strings.Repeat("c", 64),
		},
	}}
	probe := continuitySourceProbe{source: source, service: service}
	base := managedSupervisorReceipt{
		SchemaVersion: 1, Command: "status", Status: "running", Ready: true,
		Instance: "ba1b", SandboxID: source.Report.SandboxID,
		ProfileID: "opencode", ProfileDigest: "sha256:" + strings.Repeat("b", 64), ProfileRevision: 1,
		SessionID: source.Report.NativeSessionID, NativeProjectID: source.Report.NativeProjectID,
		NativeLocationDigest: source.Report.NativeLocationDigest,
		InstructionRevision:  1, InstructionDigest: "sha256:" + strings.Repeat("c", 64), InstructionApplied: true,
	}
	setLater := func(receipt *managedSupervisorReceipt, from string) {
		switch from {
		case "instance":
			receipt.Instance = "foreign"
			fallthrough
		case "sandbox":
			receipt.SandboxID = "foreign"
			fallthrough
		case "profile_id":
			receipt.ProfileID = "foreign"
			fallthrough
		case "profile_digest":
			receipt.ProfileDigest = "foreign"
			fallthrough
		case "profile_revision":
			receipt.ProfileRevision = 2
			fallthrough
		case "session":
			receipt.SessionID = "foreign"
			fallthrough
		case "native_project":
			receipt.NativeProjectID = "foreign"
			fallthrough
		case "native_location":
			receipt.NativeLocationDigest = "foreign"
			fallthrough
		case "instruction_revision":
			receipt.InstructionRevision = 2
			fallthrough
		case "instruction_digest":
			receipt.InstructionDigest = "foreign"
			fallthrough
		case "instruction_applied":
			receipt.InstructionApplied = false
		}
	}
	failAt := func(from string) func(*managedSupervisorReceipt) {
		return func(receipt *managedSupervisorReceipt) { setLater(receipt, from) }
	}
	cases := []struct {
		name    string
		execErr error
		mutate  func(*managedSupervisorReceipt)
		code    string
	}{
		{name: "success", code: ""},
		{name: "exec_error", execErr: errors.New("transport failure"), code: "exec_error"},
		{name: "not_ready", mutate: func(receipt *managedSupervisorReceipt) { receipt.Ready = false }, code: "not_ready"},
		{name: "instance_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.Instance = "foreign" }, code: "instance_mismatch"},
		{name: "sandbox_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.SandboxID = "foreign" }, code: "sandbox_mismatch"},
		{name: "profile_id_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.ProfileID = "foreign" }, code: "profile_id_mismatch"},
		{name: "profile_digest_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.ProfileDigest = "foreign" }, code: "profile_digest_mismatch"},
		{name: "profile_revision_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.ProfileRevision = 2 }, code: "profile_revision_mismatch"},
		{name: "session_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.SessionID = "foreign" }, code: "session_mismatch"},
		{name: "native_project_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.NativeProjectID = "foreign" }, code: "native_project_mismatch"},
		{name: "native_location_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.NativeLocationDigest = "foreign" }, code: "native_location_mismatch"},
		{name: "instruction_revision_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.InstructionRevision = 2 }, code: "instruction_revision_mismatch"},
		{name: "instruction_digest_mismatch", mutate: func(receipt *managedSupervisorReceipt) { receipt.InstructionDigest = "foreign" }, code: "instruction_digest_mismatch"},
		{name: "instruction_not_applied", mutate: func(receipt *managedSupervisorReceipt) { receipt.InstructionApplied = false }, code: "instruction_not_applied"},
		{name: "exec_error_wins_over_every_later_member", execErr: errors.New("transport failure"), mutate: func(receipt *managedSupervisorReceipt) {
			receipt.Ready = false
			setLater(receipt, "instance")
		}, code: "exec_error"},
		{name: "not_ready_wins_over_every_later_member", mutate: func(receipt *managedSupervisorReceipt) {
			receipt.Ready = false
			setLater(receipt, "instance")
		}, code: "not_ready"},
		{name: "instance_wins_over_every_later_member", mutate: failAt("instance"), code: "instance_mismatch"},
		{name: "sandbox_wins_over_every_later_member", mutate: failAt("sandbox"), code: "sandbox_mismatch"},
		{name: "profile_id_wins_over_every_later_member", mutate: failAt("profile_id"), code: "profile_id_mismatch"},
		{name: "profile_digest_wins_over_every_later_member", mutate: failAt("profile_digest"), code: "profile_digest_mismatch"},
		{name: "profile_revision_wins_over_every_later_member", mutate: failAt("profile_revision"), code: "profile_revision_mismatch"},
		{name: "session_wins_over_every_later_member", mutate: failAt("session"), code: "session_mismatch"},
		{name: "native_project_wins_over_every_later_member", mutate: failAt("native_project"), code: "native_project_mismatch"},
		{name: "native_location_wins_over_every_later_member", mutate: failAt("native_location"), code: "native_location_mismatch"},
		{name: "instruction_revision_wins_over_every_later_member", mutate: failAt("instruction_revision"), code: "instruction_revision_mismatch"},
		{name: "instruction_digest_wins_over_not_applied", mutate: failAt("instruction_digest"), code: "instruction_digest_mismatch"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			receipt := base
			if test.mutate != nil {
				test.mutate(&receipt)
			}
			if got := runningReceiptFailureCode(test.execErr, receipt, probe); got != test.code {
				t.Fatalf("first failed member code = %q, want %q", got, test.code)
			}
		})
	}
}
