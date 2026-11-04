package reconcile

import (
	"testing"
)

// The production default must remain the single F1 candidate: no adoption, no
// installed-digest inference, and neither adopted closure digest is a
// producer-declarable identity.
func TestControllerMaterializerDefaultAcceptsOnlyF1Candidate(t *testing.T) {
	t.Setenv(controllerMaterializerAdoptionEnv, "")
	for _, declared := range []string{
		"sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
		"sha256:c95f1024f320675c562f8e277ab5a4430eb3216895e17d993e8da84ab1211b5b",
		"sha256:c7a75b7f453e8da6c1f56b628096ae571d006e0ce4406169b04872645e0fbc02",
		"sha256:8a5599ebfbb6493cacb4da72c10041a0cadc72309c0693769e9094c3424ff305",
		"sha256:65d499fa09fa0e583f5220c69926bfc1883665747903dd4ce7deddd92635f2b4",
		"sha256:f6f3358fd2f5e1d9e21b01300328555b5b8869b850367c34e8b662de00db254f",
		"sha256:4c1dd1cdafdc2d34988bbe00f7595349f932f97288ffbafb361ed6c942197aaa",
		"",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if got, err := controllerMaterializer(declared); err == nil || got != "" {
			t.Fatalf("unapproved declared digest %q resolved to %q (err=%v)", declared, got, err)
		}
	}
	got, err := controllerMaterializer(controllerMaterializerCandidateDigest)
	if err != nil || got != controllerMaterializerCandidateDigest {
		t.Fatalf("F1 candidate did not resolve verbatim: %q %v", got, err)
	}
}

// An adopted installed closure is visible only under the exact approval id, and
// only for the exact producer-declared digest that record adopts.
func TestControllerMaterializerAdoptionIsExact(t *testing.T) {
	for _, record := range controllerMaterializerAdoptions {
		t.Setenv(controllerMaterializerAdoptionEnv, record.ID)
		got, err := controllerMaterializer(record.DeclaredDigest)
		if err != nil || got != record.AdoptedDigest {
			t.Fatalf("%s: adopted declared digest resolved to %q (err=%v)", record.ID, got, err)
		}
		// The F1 candidate keeps working unchanged even with a venue record selected.
		if got, err := controllerMaterializer(controllerMaterializerCandidateDigest); err != nil || got != controllerMaterializerCandidateDigest {
			t.Fatalf("%s: candidate changed under adoption: %q %v", record.ID, got, err)
		}
		for _, declared := range []string{
			record.AdoptedDigest,
			"",
			"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		} {
			if got, err := controllerMaterializer(declared); err == nil || got != "" {
				t.Fatalf("%s: declared digest %q resolved to %q under adoption (err=%v)",
					record.ID, declared, got, err)
			}
		}
	}
}

// R-WP95-1: the WP-95 record adopts the closure measured from the rebuilt
// seven-field sandbox image and supersedes the WP-93 installed closure, while a
// venue that still names the WP-93 id keeps resolving the older one.
func TestControllerMaterializerWP95RecordSupersedesWP93(t *testing.T) {
	wp93, wp95 := controllerMaterializerAdoptions[0], controllerMaterializerAdoptions[1]
	if wp95.ID != "WP95-MAT-ADOPT-1" {
		t.Fatalf("unexpected WP-95 record: %+v", wp95)
	}
	if wp95.DeclaredDigest != wp93.DeclaredDigest {
		t.Fatalf("the producer-declared pin moved: %q vs %q", wp93.DeclaredDigest, wp95.DeclaredDigest)
	}
	if wp95.AdoptedDigest == wp93.AdoptedDigest {
		t.Fatalf("the WP-95 record does not supersede the WP-93 closure: %q", wp95.AdoptedDigest)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp95.ID)
	if got, err := controllerMaterializer(wp95.DeclaredDigest); err != nil || got != wp95.AdoptedDigest {
		t.Fatalf("WP-95 record resolved to %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp93.ID)
	if got, err := controllerMaterializer(wp93.DeclaredDigest); err != nil || got != wp93.AdoptedDigest {
		t.Fatalf("WP-93 record resolved to %q (err=%v)", got, err)
	}
	// The WP-95 adopted digest is never a declarable producer identity.
	t.Setenv(controllerMaterializerAdoptionEnv, wp95.ID)
	if got, err := controllerMaterializer(wp95.AdoptedDigest); err == nil || got != "" {
		t.Fatalf("adopted closure accepted as declared: %q (err=%v)", got, err)
	}
}

// R-WP98-1: the WP-98 record adopts the closure measured from the rebuilt
// native-role sandbox image and supersedes the WP-95 installed closure; the WP-95
// id keeps resolving its own older closure, and the WP-99 record adopts the r2
// receipt-field-fix image closure without disturbing either.
func TestControllerMaterializerWP98AndWP99RecordsSupersede(t *testing.T) {
	wp95, wp98, wp99 := controllerMaterializerAdoptions[1], controllerMaterializerAdoptions[2],
		controllerMaterializerAdoptions[3]
	if wp98.ID != "WP98-MAT-ADOPT-1" || wp99.ID != "WP99-MAT-ADOPT-1" {
		t.Fatalf("unexpected WP-98/WP-99 records: %+v %+v", wp98, wp99)
	}
	if wp98.DeclaredDigest != wp95.DeclaredDigest || wp99.DeclaredDigest != wp95.DeclaredDigest {
		t.Fatalf("the producer-declared pin moved: %q %q %q",
			wp95.DeclaredDigest, wp98.DeclaredDigest, wp99.DeclaredDigest)
	}
	if wp98.AdoptedDigest == wp95.AdoptedDigest || wp99.AdoptedDigest == wp98.AdoptedDigest {
		t.Fatalf("the new records do not supersede their predecessors: %+v %+v", wp98, wp99)
	}
	for _, record := range []controllerMaterializerAdoption{wp98, wp99} {
		t.Setenv(controllerMaterializerAdoptionEnv, record.ID)
		if got, err := controllerMaterializer(record.DeclaredDigest); err != nil || got != record.AdoptedDigest {
			t.Fatalf("%s record resolved to %q (err=%v)", record.ID, got, err)
		}
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp95.ID)
	if got, err := controllerMaterializer(wp95.DeclaredDigest); err != nil || got != wp95.AdoptedDigest {
		t.Fatalf("WP-95 record resolved to %q (err=%v)", got, err)
	}
	// Neither newly adopted closure is ever a declarable producer identity.
	for _, record := range []controllerMaterializerAdoption{wp98, wp99} {
		t.Setenv(controllerMaterializerAdoptionEnv, record.ID)
		if got, err := controllerMaterializer(record.AdoptedDigest); err == nil || got != "" {
			t.Fatalf("adopted closure accepted as declared: %q (err=%v)", got, err)
		}
	}
}

// Near-miss approval ids (prefix, case, next revision, whitespace inside) must
// not select a record.
func TestControllerMaterializerAdoptionRequiresExactApprovalID(t *testing.T) {
	record := controllerMaterializerAdoptions[1]
	for _, id := range []string{
		// Surrounding whitespace is deliberately trimmed; every other near miss
		// (prefix, case, next revision, suffix) must not select the record.
		"", "WP95-MAT-ADOPT", "wp95-mat-adopt-1", "WP95-MAT-ADOPT-2",
		"WP95-MAT-ADOPT-1-x", "WP95-MAT-ADOPT-1 " + record.ID,
	} {
		t.Setenv(controllerMaterializerAdoptionEnv, id)
		if got, err := controllerMaterializer(record.DeclaredDigest); err == nil || got != "" {
			t.Fatalf("approval id %q selected adoption -> %q (err=%v)", id, got, err)
		}
	}
}

// The compiled records are the approval. Pin their exact bytes so a silent edit
// of either digest, the closure version or the scope fails here.
func TestControllerMaterializerAdoptionRecordPinned(t *testing.T) {
	if len(controllerMaterializerAdoptions) != 10 {
		t.Fatalf("expected exactly ten adoption records, found %d", len(controllerMaterializerAdoptions))
	}
	want := [10]controllerMaterializerAdoption{{
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
		ID:             "WP196-MAT-ADOPT-1",
		DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
		AdoptedDigest:  "sha256:ed0d9bf65aa5254ba46aed31780dbfe79c0ba7aa76a5b0ee3b67d871150e0149",
		ClosureVersion: "warpmetal-workspace-content-v1",
		Scope:          "venue:wp196-r13b-installed-closure",
		Approval:       "WP196_R13B_NATIVE_CLOSURE / R-WP195-1",
	}, {
		ID:             "WP211-P5-MAT-ADOPT-1",
		DeclaredDigest: "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333",
		AdoptedDigest:  "sha256:58910c85dca8fbe4435d16bb716f5bb0facda7f3987c2a7e65d207d068c6df3f",
		ClosureVersion: "warpmetal-workspace-content-v1",
		Scope:          "venue:wp211-p5-installed-a",
		Approval:       "WP211_P5_INSTALLED_CHAIN",
	}}
	for index, record := range controllerMaterializerAdoptions {
		if record != want[index] {
			t.Fatalf("adoption record %d changed:\n got %+v\nwant %+v", index, record, want[index])
		}
		if record.DeclaredDigest == controllerMaterializerCandidateDigest || record.AdoptedDigest == record.DeclaredDigest {
			t.Fatalf("adoption record collapses the two identities: %+v", record)
		}
	}
}

// R-WP106-1 (WP-107 venue): the WP-106 record adopts the closure measured from
// the r4 credential-binding image and supersedes the WP-99 installed closure.
// The superseded WP-99 id keeps resolving its own older closure, the r4 closure
// is never a declarable producer identity, and an empty/unknown approval id
// still leaves the production F1 default untouched.
func TestControllerMaterializerWP106RecordAdoptsR4Closure(t *testing.T) {
	wp99, wp106 := controllerMaterializerAdoptions[3], controllerMaterializerAdoptions[4]
	if wp106.ID != "WP106-MAT-ADOPT-1" {
		t.Fatalf("unexpected WP-106 record: %+v", wp106)
	}
	if wp106.DeclaredDigest != wp99.DeclaredDigest {
		t.Fatalf("the producer-declared pin moved: %q vs %q",
			wp99.DeclaredDigest, wp106.DeclaredDigest)
	}
	if wp106.AdoptedDigest != "sha256:000220714ca08f6472294101b0169e03376e3f724b5dbf6a57f1ce63c0bf9856" {
		t.Fatalf("the WP-106 record does not carry the measured r4 closure: %q", wp106.AdoptedDigest)
	}
	if wp106.AdoptedDigest == wp99.AdoptedDigest {
		t.Fatalf("the WP-106 record does not supersede the WP-99 closure: %q", wp106.AdoptedDigest)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp106.ID)
	if got, err := controllerMaterializer(wp106.DeclaredDigest); err != nil || got != wp106.AdoptedDigest {
		t.Fatalf("WP-106 record resolved to %q (err=%v)", got, err)
	}
	// The superseded record is retained and still selects its own closure.
	t.Setenv(controllerMaterializerAdoptionEnv, wp99.ID)
	if got, err := controllerMaterializer(wp99.DeclaredDigest); err != nil || got != wp99.AdoptedDigest {
		t.Fatalf("WP-99 record no longer resolves: %q (err=%v)", got, err)
	}
	// The adopted closure is never a declarable producer identity.
	t.Setenv(controllerMaterializerAdoptionEnv, wp106.ID)
	if got, err := controllerMaterializer(wp106.AdoptedDigest); err == nil || got != "" {
		t.Fatalf("adopted closure accepted as declared: %q (err=%v)", got, err)
	}
	// The r4 venue must set the env: without it the default fails closed.
	t.Setenv(controllerMaterializerAdoptionEnv, "")
	if got, err := controllerMaterializer(wp106.DeclaredDigest); err == nil || got != "" {
		t.Fatalf("r4 declared digest resolved without an adoption id: %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, "WP107-MAT-ADOPT-1")
	if got, err := controllerMaterializer(wp106.DeclaredDigest); err == nil || got != "" {
		t.Fatalf("unknown approval id selected the r4 closure: %q (err=%v)", got, err)
	}
}

// R-WP124-2 (WP-126 venue): the WP-125 record adopts the closure measured from
// the r6 plugin-ship image (the scoped manager-plugin deny), supersedes the
// WP-106 r4 closure, keeps the r4 record resolvable, and leaves the production
// F1 default untouched.
func TestControllerMaterializerWP125RecordAdoptsR6Closure(t *testing.T) {
	wp106, wp125 := controllerMaterializerAdoptions[4], controllerMaterializerAdoptions[5]
	if wp125.ID != "WP125-MAT-ADOPT-1" {
		t.Fatalf("unexpected WP-125 record: %+v", wp125)
	}
	if wp125.DeclaredDigest != wp106.DeclaredDigest {
		t.Fatalf("the producer-declared pin moved: %q vs %q", wp106.DeclaredDigest, wp125.DeclaredDigest)
	}
	if wp125.AdoptedDigest != "sha256:ad5b6303aa91abdce790a926c698485b40dc3317a55dd26a4e1d9adea8b4bbc8" {
		t.Fatalf("the WP-125 record does not carry the measured r6 closure: %q", wp125.AdoptedDigest)
	}
	if wp125.AdoptedDigest == wp106.AdoptedDigest {
		t.Fatalf("the WP-125 record does not supersede the WP-106 closure: %q", wp125.AdoptedDigest)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp125.ID)
	if got, err := controllerMaterializer(wp125.DeclaredDigest); err != nil || got != wp125.AdoptedDigest {
		t.Fatalf("WP-125 record resolved to %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp106.ID)
	if got, err := controllerMaterializer(wp106.DeclaredDigest); err != nil || got != wp106.AdoptedDigest {
		t.Fatalf("WP-106 record no longer resolves: %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, "")
	if got, err := controllerMaterializer(wp125.DeclaredDigest); err == nil || got != "" {
		t.Fatalf("r6 declared digest resolved without an adoption id: %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp125.ID)
	if got, err := controllerMaterializer(wp125.AdoptedDigest); err == nil || got != "" {
		t.Fatalf("adopted closure accepted as declared: %q (err=%v)", got, err)
	}
}

// R-WP139-1 (WP-140 venue): the WP-140 record adopts the closure measured from
// the r7 qualification-hook-scope image, supersedes the WP-125 r6 closure, keeps
// the r6 record resolvable, and leaves the production F1 default untouched.
func TestControllerMaterializerWP140RecordAdoptsR7Closure(t *testing.T) {
	wp125, wp140 := controllerMaterializerAdoptions[5], controllerMaterializerAdoptions[6]
	if wp140.ID != "WP140-MAT-ADOPT-1" {
		t.Fatalf("unexpected WP-140 record: %+v", wp140)
	}
	if wp140.DeclaredDigest != wp125.DeclaredDigest {
		t.Fatalf("the producer-declared pin moved: %q vs %q", wp125.DeclaredDigest, wp140.DeclaredDigest)
	}
	if wp140.AdoptedDigest != "sha256:f6f3358fd2f5e1d9e21b01300328555b5b8869b850367c34e8b662de00db254f" {
		t.Fatalf("the WP-140 record does not carry the measured r7 closure: %q", wp140.AdoptedDigest)
	}
	if wp140.AdoptedDigest == wp125.AdoptedDigest {
		t.Fatalf("the WP-140 record does not supersede the WP-125 closure: %q", wp140.AdoptedDigest)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp140.ID)
	if got, err := controllerMaterializer(wp140.DeclaredDigest); err != nil || got != wp140.AdoptedDigest {
		t.Fatalf("WP-140 record resolved to %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp125.ID)
	if got, err := controllerMaterializer(wp125.DeclaredDigest); err != nil || got != wp125.AdoptedDigest {
		t.Fatalf("WP-125 record no longer resolves: %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, "")
	if got, err := controllerMaterializer(wp140.DeclaredDigest); err == nil || got != "" {
		t.Fatalf("r7 declared digest resolved without an adoption id: %q (err=%v)", got, err)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, wp140.ID)
	if got, err := controllerMaterializer(wp140.AdoptedDigest); err == nil || got != "" {
		t.Fatalf("adopted closure accepted as declared: %q (err=%v)", got, err)
	}
}
