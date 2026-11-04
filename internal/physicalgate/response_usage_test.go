package physicalgate

import (
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"strings"
	"testing"
)

// Named material rule: original network usage, not RPC-supplied price, releases
// the singleton. The installed Linux journal reader cannot run on Darwin here.
func TestNativeOriginalUsageRejectsReflectedPriceOrAmbiguousCompletion(t *testing.T) {
	raw := []byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"source_response\",\"status\":\"completed\",\"model\":\"gpt-4.1-mini-2025-04-14\",\"usage\":{\"input_tokens\":100,\"output_tokens\":10,\"input_tokens_details\":{\"cached_tokens\":50}}}}\n\n")
	for _, consumer := range []string{"parent", "product", "qualification"} {
		want := int64(41)
		if consumer == "product" {
			want = 56
		}
		if err := verifyOriginalUsage(consumer, raw, 200, want); err != nil {
			t.Fatal(consumer, err)
		}
		if err := verifyOriginalUsage(consumer, raw, 200, want+1); err == nil {
			t.Fatal("reflected wrong usage admitted", consumer)
		}
		if err := verifyOriginalUsage(consumer, append(append([]byte{}, raw...), raw...), 200, want); err == nil {
			t.Fatal("duplicate completion admitted")
		}
		if err := verifyOriginalUsage(consumer, raw, 400, want); err == nil {
			t.Fatal("unmeasured failed-response usage assumed")
		}
	}
	flash := []byte(strings.ReplaceAll(string(raw), "gpt-4.1-mini-2025-04-14", "deepseek-flash"))
	flash = []byte(strings.Replace(string(flash), `"usage":`, `"output":[],"usage":`, 1))
	id, cost, err := ProviderResponseUsage(providerpolicy.FlashDigest, flash, 200)
	if err != nil || id != "source_response" || cost != 42 {
		t.Fatal("closed Flash original usage", id, cost, err)
	}
	if _, _, err = ProviderResponseUsage(providerpolicy.FlashDigest, append(append([]byte{}, flash...), flash...), 200); err == nil {
		t.Fatal("Flash duplicate completion released hold")
	}
}
