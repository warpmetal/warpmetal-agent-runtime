package reconcile

import (
	"errors"
	"os"
	"strings"
)

// controllerMaterializerCandidateDigest is F1's independently approved exact
// workspace-content materializer closure. It is the ONLY identity accepted by
// default and it is unchanged by WP-93: an operation whose producer-declared
// materializerDigest equals this value is staged against it verbatim.
//
// It is a source candidate, NOT a ready/installed flag: the packaged Supervisor
// recomputes the same closure from actual installed files and returns it in the
// materialize-profile receipt, which is then compared byte-for-byte.
const controllerMaterializerCandidateDigest = "sha256:8744191056041ad646dddce209280b449927a6965935e2baf0a0969343973396"

// controllerMaterializerAdoptionEnv selects one exact compiled approval/adoption
// record by its approval id. Empty or unknown ids leave the default single-pin
// behaviour untouched, so production continues to fail closed on any digest that
// is not controllerMaterializerCandidateDigest.
const controllerMaterializerAdoptionEnv = "WARPMETAL_RUNTIME_MATERIALIZER_ADOPTION"

// controllerMaterializerAdoption is an explicit, documented approval/adoption
// record. It is the only way a producer-declared digest that is not the F1
// candidate may name the installed workspace-content closure.
type controllerMaterializerAdoption struct {
	// ID is the exact value the venue must name in controllerMaterializerAdoptionEnv.
	ID string
	// DeclaredDigest is the producer-declared operation materializerDigest that
	// this record adopts. The Runtime never invents a producer digest.
	DeclaredDigest string
	// AdoptedDigest is the approved installed workspace-content closure digest,
	// i.e. the value the packaged Supervisor measures from installed files with
	// materializer_source_digest() for closure version ClosureVersion.
	AdoptedDigest string
	// ClosureVersion is the closed closure format the adopted digest covers.
	ClosureVersion string
	// Scope names the bounded test/venue use this record is approved for.
	Scope string
	// Approval names the recorded approval decision this record implements.
	Approval string
}

// controllerMaterializerAdoptions holds the compiled adoption records. There is
// deliberately no wildcard, prefix, version-range or "any installed digest"
// member: a record matches only when both the selected approval id and the
// producer-declared digest match exactly.
//
// WP93-MAT-ADOPT-1 (R-WP92-2): the backend composer declared
// sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333.
// Its own source comment states that value is a composer source implementation
// pin and must never be labelled as the sandbox materializer or installed bytes.
// The installed workspace-content closure that the packaged Supervisor measures
// (closure version warpmetal-workspace-content-v1, sandbox candidate image
// sha256:9b746cb708e53868c4f2c115e8bd2be2a707355f09a8362a9dc55e735fdd41d9) is
// sha256:c95f1024f320675c562f8e277ab5a4430eb3216895e17d993e8da84ab1211b5b.
// The record adopts that measured closure for this bounded installed-chain venue
// only; F1's candidate pin remains the production default above.
// WP95-MAT-ADOPT-1 (R-WP95-1) adopts the closure of the WP-95 sandbox candidate
// image. Widening the packaged projection decoder to the versioned seven-field
// wire changed one of the six measured workspace-content files
// (runner/warpmetal_controller_profile.py sha256:84938f80... -> sha256:435c89c1...),
// so the built image measures
// sha256:c7a75b7f453e8da6c1f56b628096ae571d006e0ce4406169b04872645e0fbc02, which
// supersedes WP93-MAT-ADOPT-1's c95f1024... The producer-declared value is
// unchanged (the backend composer pin), so only the approved installed closure
// moves. Both records are retained; a venue selects exactly one by naming its
// approval id, and an empty/unknown id still leaves the F1 default above.
// WP98-MAT-ADOPT-1 (R-WP98-1) adopts the closure of the WP-98 sandbox candidate
// image (warpmetal-sandbox-candidate:wp98-native-role-20261020-r1
// @sha256:a5c57d2199649fcce7f22a7023cc52172856eade59ae9cbd62d0e52ff0ebdf18).
// WP-98 fixed the packaged Supervisor's /api/config response-shape guard, which
// changed runner/warpmetal_opencode_supervisor.py (98c56c9b... -> 66eac223...);
// the built image therefore measures
// sha256:8a5599ebfbb6493cacb4da72c10041a0cadc72309c0693769e9094c3424ff305, which
// supersedes WP95-MAT-ADOPT-1's c7a75b7f... The producer-declared value is
// unchanged, so only the approved installed closure moves.
// WP99-MAT-ADOPT-1 (R-WP98-1 installed-boundary receipt-field fix) adopts the
// closure of the WP-98 r2 sandbox candidate image
// (warpmetal-sandbox-candidate:wp98-native-role-20261020-r2
// @sha256:4188045283337d29fe161aa25a02e9615ea543c55a953f148489067fffe6c384).
// r1 exposed the bounded native-role diagnostic as a top-level
// `nativeRoleFailure` receipt field, which the installed Runtime's strict
// managed-supervisor receipt allowlist rejects as an unknown field; r2 carries
// the identical fix and the identical other five materializer files, but
// serializes the diagnostic into the already-allowed `reason` field instead.
// That one-file change makes the r2 image measure
// sha256:65d499fa09fa0e583f5220c69926bfc1883665747903dd4ce7deddd92635f2b4.
// WP106-MAT-ADOPT-1 (R-WP106-1, consumed by WP-107) adopts the closure of the
// WP-106 r4 sandbox candidate image
// (warpmetal-sandbox-candidate:wp98-native-role-20261020-r4
// @sha256:e7e436e24ad51898ed1526762680642c72dedc40f2d15a7e3ebff7b71bbbf478).
// WP-106 fixed the native credential-binding identity: the packaged Supervisor
// now derives the six-field native projection from the seven-field Runtime wire
// instead of forwarding `toolClosureDigest` to the native credential-binding
// route (which rejects it with 400 "Expected no excess property"). That fix
// changed two of the six measured workspace-content files
// (runner/warpmetal_opencode_supervisor.py 56f12686... and
// runner/warpmetal_controller_profile.py 5d18b0bb...), so the r4 image measures
// sha256:000220714ca08f6472294101b0169e03376e3f724b5dbf6a57f1ce63c0bf9856,
// which supersedes WP99-MAT-ADOPT-1's 65d499fa... The producer-declared value is
// unchanged (the backend composer pin), so only the approved installed closure
// moves. All six records are retained; a venue selects exactly one by naming
// its approval id, and an empty/unknown id still leaves the F1 default above.
// WP125-MAT-ADOPT-1 (R-WP124-2, consumed by WP-126) adopts the closure of the
// WP-126 r6 sandbox candidate image
// (warpmetal-sandbox-candidate:wp126-plugin-ship-20261021-r6, manifest digest
// recorded in the WP-126 receipt). The WP-125 manager-plugin fix scopes the
// prompt-free staging deny to the controller agents
// (manager-plugin/index.ts 81b81a84... -> 40652333...); the other five measured
// files are byte-unchanged, so the r6 image measures
// sha256:ad5b6303aa91abdce790a926c698485b40dc3317a55dd26a4e1d9adea8b4bbc8,
// which supersedes WP106-MAT-ADOPT-1's 00022071... The producer-declared value
// is unchanged (the backend composer pin), so only the approved installed
// closure moves.
// WP140-MAT-ADOPT-1 (R-WP139-1, consumed by WP-140) adopts the closure of the
// WP-140 r7 sandbox candidate image
// (warpmetal-sandbox-candidate:wp140-qualification-scope-20261021-r7, manifest
// digest recorded in the WP-140 receipt). The WP-140 qualification-plugin fix
// scopes the controller-mode native hooks to the controller parent's activity
// (qualification-plugin/index.ts 6e6cd5e8... -> a489095a...); the other five
// measured files are byte-unchanged, so the r7 image measures
// sha256:f6f3358fd2f5e1d9e21b01300328555b5b8869b850367c34e8b662de00db254f,
// which supersedes WP125-MAT-ADOPT-1's ad5b6303... The producer-declared value
// is unchanged (the backend composer pin), so only the approved installed
// closure moves. All seven records are retained; a venue selects exactly one by
// naming its approval id, and an empty/unknown id still leaves the F1 default.
// WP140-MAT-ADOPT-2 (R-WP139-1, consumed by WP-140) adopts the r8 closure after
// the second half of the same fix: the controller-parent native configuration
// must define the co-located managed child agent, otherwise
// SessionContext.select fails with AgentNotFoundError before the guarded input
// is promoted (runner/warpmetal_opencode_supervisor.py 56f12686... ->
// a75ae062...). The r8 image therefore measures
// sha256:4c1dd1cdafdc2d34988bbe00f7595349f932f97288ffbafb361ed6c942197aaa.
// WP140-MAT-ADOPT-1 (r7) stays resolvable for the plugin-only image.
var controllerMaterializerAdoptions = [...]controllerMaterializerAdoption{{
	ID:             "WP93-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:c95f1024f320675c562f8e277ab5a4430eb3216895e17d993e8da84ab1211b5b",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp93-installed-chain",
	Approval:       "WP93_INSTALLED_CHAIN_AFTER_WIRE / R-WP92-2",
}, {
	ID:             "WP95-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:c7a75b7f453e8da6c1f56b628096ae571d006e0ce4406169b04872645e0fbc02",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp97-installed-chain",
	Approval:       "WP97_INSTALLED_CHAIN_COMPLETE / R-WP95-1",
}, {
	ID:             "WP98-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:8a5599ebfbb6493cacb4da72c10041a0cadc72309c0693769e9094c3424ff305",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp98-native-role",
	Approval:       "WP98_SUPERVISOR_NATIVE_ROLE / R-WP98-1",
}, {
	ID:             "WP99-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:65d499fa09fa0e583f5220c69926bfc1883665747903dd4ce7deddd92635f2b4",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp99-installed-chain",
	Approval:       "WP99_CHAIN_COMPLETE / R-WP98-1",
}, {
	ID:             "WP106-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:000220714ca08f6472294101b0169e03376e3f724b5dbf6a57f1ce63c0bf9856",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp107-r4-chain",
	Approval:       "WP107_R4_CHAIN / R-WP106-1",
}, {
	ID:             "WP125-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:ad5b6303aa91abdce790a926c698485b40dc3317a55dd26a4e1d9adea8b4bbc8",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp126-r6-plugin-ship",
	Approval:       "WP126_PLUGIN_SHIPPED / R-WP124-2",
}, {
	ID:             "WP140-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:f6f3358fd2f5e1d9e21b01300328555b5b8869b850367c34e8b662de00db254f",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp140-input-delivery",
	Approval:       "WP140_INPUT_DELIVERY / R-WP139-1",
}, {
	ID:             "WP140-MAT-ADOPT-2",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:4c1dd1cdafdc2d34988bbe00f7595349f932f97288ffbafb361ed6c942197aaa",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp140-input-delivery",
	Approval:       "WP140_INPUT_DELIVERY / R-WP139-1",
}, {
	// WP196-MAT-ADOPT-1 (R-WP195-1, consumed by WP-196) adopts the closure of
	// the installed r13b sandbox candidate image
	// (warpmetal-sandbox-candidate:wp190-qualclient-20261023-r13b, manifest
	// digest recorded in the WP-195 receipt). The r13b closure is the WP-190
	// qualification-client supervisor/plugin set: the packaged Supervisor
	// measures runner/warpmetal_opencode_supervisor.py,
	// runner/warpmetal_controller_profile.py and the image-owned plugin/
	// launcher files as
	// sha256:ed0d9bf65aa5254ba46aed31780dbfe79c0ba7aa76a5b0ee3b67d871150e0149.
	// The producer-declared value is the r5 composer pin
	// (sha256:f27cb530..., unchanged in the backend image); only the approved
	// installed closure moves. This replaces WP-195's test-only container-local
	// bind-mount over warpmetal_controller_profile.py: neither the image nor a
	// backend byte is altered, and no digest is inferred from a prefix, the
	// venue or the installed binary.
	ID:             "WP196-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:ed0d9bf65aa5254ba46aed31780dbfe79c0ba7aa76a5b0ee3b67d871150e0149",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp196-r13b-installed-closure",
	Approval:       "WP196_R13B_NATIVE_CLOSURE / R-WP195-1",
}, {
	// WP211-P5-MAT-ADOPT-1 (WP-211 P5b, consumed by the P5b TEST venue) adopts
	// the measured installed workspace-content closure of the rebuilt TEST image
	// warpmetal-sandbox-candidate:wp211c1-p5b (config digest
	// sha256:af32c9fb..., OCI manifest sha256:df062c71...). P5 found that the
	// image layout declared manager-plugin/index.ts and
	// qualification-plugin/index.ts but did not COPY them, so the packaged
	// Supervisor could not measure its own six-file closure and controller-parent
	// staging failed closed. The packaging copies were added, the image rebuilt,
	// and the closure measured from the installed files with
	// materializer_source_digest() (closure version warpmetal-workspace-content-v1):
	// sha256:58910c85dca8fbe4435d16bb716f5bb0facda7f3987c2a7e65d207d068c6df3f.
	// The producer-declared value remains the unchanged r5 composer pin
	// (sha256:f27cb530...); only the approved installed closure moves. Production
	// default (F1 candidate) is untouched and still required to be the only
	// producer-declarable identity without an explicitly selected record.
	ID:             "WP211-P5-MAT-ADOPT-1",
	DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
	AdoptedDigest:  "sha256:58910c85dca8fbe4435d16bb716f5bb0facda7f3987c2a7e65d207d068c6df3f",
	ClosureVersion: "warpmetal-workspace-content-v1",
	Scope:          "venue:wp211-p5-installed-a",
	Approval:       "WP211_P5_INSTALLED_CHAIN",
}}

// errControllerMaterializer is the retained fail-closed staging error. It is
// returned for an unapproved identity, for an unselected or unknown approval id,
// and for a declared digest that no selected record covers.
var errControllerMaterializer = errors.New("exact approved materializer/tool closure dependency pending")

// controllerMaterializer resolves the closure digest the Supervisor must see for
// this operation. The default path returns the F1 candidate unchanged. Any other
// declared digest requires the exact compiled adoption record selected by
// controllerMaterializerAdoptionEnv; nothing is inferred from the operation, the
// venue, the installed binary, a prefix or a backend source hash.
func controllerMaterializer(declared string) (string, error) {
	if declared == controllerMaterializerCandidateDigest {
		return declared, nil
	}
	selected := strings.TrimSpace(os.Getenv(controllerMaterializerAdoptionEnv))
	if selected == "" {
		return "", errControllerMaterializer
	}
	for _, record := range controllerMaterializerAdoptions {
		if record.ID == selected && record.DeclaredDigest == declared {
			return record.AdoptedDigest, nil
		}
	}
	return "", errControllerMaterializer
}
