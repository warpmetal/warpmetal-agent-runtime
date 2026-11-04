package reconcile

import "testing"

// WP-211 P5b: the rebuilt TEST image closure is adopted exactly once, only under
// its recorded approval id and only for the unchanged producer-declared composer
// pin; unknown ids, adopted digests and foreign declared digests stay refused.
func TestControllerMaterializerWP211P5RecordIsExact(t *testing.T) {
	var record *controllerMaterializerAdoption
	for i := range controllerMaterializerAdoptions {
		if controllerMaterializerAdoptions[i].ID == "WP211-P5-MAT-ADOPT-1" {
			record = &controllerMaterializerAdoptions[i]
		}
	}
	if record == nil {
		t.Fatal("WP211-P5-MAT-ADOPT-1 record missing")
	}
	if record.DeclaredDigest != "sha256:f27cb5303f1fb1449eaac89112d9b2feaa324adeef13e3e0df998b7c145e3333" {
		t.Fatalf("unexpected declared digest %q", record.DeclaredDigest)
	}
	if record.AdoptedDigest != "sha256:58910c85dca8fbe4435d16bb716f5bb0facda7f3987c2a7e65d207d068c6df3f" {
		t.Fatalf("unexpected adopted digest %q", record.AdoptedDigest)
	}
	if record.ClosureVersion != "warpmetal-workspace-content-v1" ||
		record.Scope != "venue:wp211-p5-installed-a" ||
		record.Approval != "WP211_P5_INSTALLED_CHAIN" {
		t.Fatalf("unexpected record metadata: %+v", record)
	}
	t.Setenv(controllerMaterializerAdoptionEnv, record.ID)
	got, err := controllerMaterializer(record.DeclaredDigest)
	if err != nil || got != record.AdoptedDigest {
		t.Fatalf("record did not resolve: %q %v", got, err)
	}
	// An unknown venue id must not select the record even with the declared pin.
	t.Setenv(controllerMaterializerAdoptionEnv, "WP211-P5-MAT-ADOPT-UNKNOWN")
	if got, err := controllerMaterializer(record.DeclaredDigest); err == nil || got != "" {
		t.Fatalf("unknown approval id resolved the record: %q %v", got, err)
	}
	// An adopted digest is not itself a producer-declarable identity, and a
	// foreign declared digest never resolves under the selected record.
	t.Setenv(controllerMaterializerAdoptionEnv, record.ID)
	for _, declared := range []string{
		record.AdoptedDigest,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if got, err := controllerMaterializer(declared); err == nil || got != "" {
			t.Fatalf("declared %q resolved under P5b record: %q %v", declared, got, err)
		}
	}
}
