package reconcile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Extend the normal owner/role attachment journey through the actual HTTP
// client using an unchanged current backend HTTP SOURCE context. No captured
// source context/signature becomes installed execution authority.
func testCurrentSingleContextSource(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("WARPMETAL_SINGLE_CONTEXT_SOURCE"))
	var packet struct {
		Context []json.RawMessage
		Policy  qualification.ControllerPolicy
	}
	if err != nil || json.Unmarshal(raw, &packet) != nil || len(packet.Context) != 3 {
		t.Fatal("current backend context source", err)
	}
	var header struct {
		PreparationID string `json:"preparationId"`
	}
	if json.Unmarshal(packet.Context[1], &header) != nil {
		t.Fatal("context identity")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/internal/runtime/workspace-workflow/controller-preparations/"+header.PreparationID+"/workflow-context" || r.Header.Get("Authorization") != "Bearer rtn_source" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_single" {
			t.Error("current context transport changed")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(packet.Context[1])
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	c, err := client.ControllerWorkflowContext(context.Background(), header.PreparationID, "wfl_source_single")
	if err != nil {
		t.Fatal("actual context4 client", err)
	}
	if c.FormatVersion != 4 || c.Target.Kind != "manager_work_intent" || model.WorkspaceDigest(c) != model.WorkspaceDigest(packet.Context[1]) || packet.Policy.ValidateContext(c) != nil {
		t.Fatal("current paired policy/context identity")
	}
	var value map[string]any
	_ = json.Unmarshal(packet.Context[1], &value)
	target := value["target"].(map[string]any)
	intent := target["intent"].(map[string]any)
	advice := target["advice"].(map[string]any)
	workflow := intent["prepareBody"].(map[string]any)["content"].(map[string]any)["workflowPacket"].(map[string]any)
	lane := map[string]any{"laneId": intent["laneId"], "packetRefs": []any{map[string]any{"packetId": workflow["packetId"], "packetRevision": workflow["packetRevision"]}}, "dependencies": []any{}, "writeScope": workflow["writeScope"], "requestedParallelism": 1, "reason": "SOURCE exact current single lane"}
	body := map[string]any{"formatVersion": 1, "requestId": c.WorkflowRequestID, "plan": c.Plan, "expectedAdviceRevision": advice["adviceRevision"], "choice": "adopt", "lanes": []any{lane}, "reason": "SOURCE parser only"}
	encoded, _ := json.Marshal(body)
	if _, err = model.ControllerProposal(c, string(encoded)); err != nil {
		t.Fatal("current single proposal", err)
	}
	body["lanes"] = []any{lane, lane}
	encoded, _ = json.Marshal(body)
	if _, err = model.ControllerProposal(c, string(encoded)); err == nil {
		t.Fatal("second initial lane admitted")
	}
	t.Log("actual TLS client/current context4/policy selection/proposal; original backend source IDs, no native output or accepted handle")
}
