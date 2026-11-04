package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// P5/R2 boundary: the operation wire stays v1 while the additive v2
// configuration carries the closed agentSetup declaration. A v1 configuration
// can never smuggle a kit and a v2 configuration must carry one.
func TestApplicationConfigurationVersionBranches(t *testing.T) {
	base := WorkspaceApplicationOperation{FormatVersion: 1, Kind: "configuration_application"}
	base.Dependencies.FormatVersion = 1
	base.Dependencies.Phase = "prompt_free"
	base.Configuration.FormatVersion = 1
	base.Configuration.AgentSetup = json.RawMessage(`{"formatVersion":2}`)
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "invalid workspace application operation") {
		t.Fatalf("v1 configuration with agentSetup must be refused, got %v", err)
	}
	base.Configuration.FormatVersion = 2
	base.Configuration.AgentSetup = nil
	if err := base.Validate(); err == nil {
		t.Fatal("v2 configuration without agentSetup must be refused")
	}
}
