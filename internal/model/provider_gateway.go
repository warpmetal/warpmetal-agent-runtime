package model

import (
	"encoding/json"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// This file defines the additive P2d sandbox contract for scoped provider
// gateways. A sandbox may declare at most a small, bounded set of provider
// gateway requirements; the Runtime starts exactly one sandbox-facing gateway
// per requirement, inside that sandbox's workspace, only while the sandbox is
// running. The contract intentionally carries non-secret platform metadata
// only: the opened Box credential is resolved by credential id at runtime and
// never travels through the manifest. Unknown fields (including any attempt to
// pass an envelope, ciphertext or secret value) are rejected by the strict
// manifest decoder because the requirement and tool types are plain structs
// decoded by the closed Sandbox/Manifest codecs.
const (
	// MaxProviderGatewaysPerSandbox bounds the scoped provider gateways one
	// sandbox may declare.
	MaxProviderGatewaysPerSandbox = 8
	// MaxProviderGatewayTools bounds one gateway's declared tool allowlist.
	MaxProviderGatewayTools = 64
	// MaxProviderGatewayInputSchemaBytes bounds one advertised tool input
	// schema. The provider gateway itself accepts larger schemas, but P2d
	// deliberately keeps the manifest document small: a 16 KiB ceiling holds
	// the complete tool set of any realistic provider.
	MaxProviderGatewayInputSchemaBytes = 16 << 10
	// MaxProviderGatewayDescriptionBytes bounds one advertised tool
	// description, matching the gateway's own declared-description ceiling.
	MaxProviderGatewayDescriptionBytes = 4 << 10
	// maxProviderGatewayIdentifierBytes bounds every non-secret identifier in
	// one requirement. Identifiers name sockets, logs and provider accounts;
	// they are never secrets and never carry arbitrary data.
	maxProviderGatewayIdentifierBytes = 128
)

var (
	// providerGatewayRunIDPattern is the bounded, traversal-free run id shape.
	// The run id names the gateway's Unix socket file, so only letters, digits,
	// '_' and '-' are accepted.
	providerGatewayRunIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	// providerGatewayCredentialIDPattern bounds the platform credential id. It
	// is a non-secret identifier: the corresponding sealed capability is
	// opened in memory by the Runtime and never accepted over the manifest.
	providerGatewayCredentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	// providerGatewayProviderIDPattern matches the platform's tool-provider
	// identifier grammar (for example "github").
	providerGatewayProviderIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	// providerGatewayToolNamePattern is the MCP-safe declared tool name shape,
	// identical to the gateway's own allowlist: no whitespace, slashes or
	// JSON-RPC control characters.
	providerGatewayToolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// ProviderGatewayRequirement is one scoped provider gateway a running sandbox
// needs. It identifies the credential by id only; the Runtime opens the sealed
// credential locally and keeps the plaintext in memory for the gateway's
// lifetime.
type ProviderGatewayRequirement struct {
	// RunID is the bounded safe identifier that owns the gateway. It names the
	// per-run Unix socket, so it must be stable across reconcile passes and
	// change whenever the requirement is replaced.
	RunID string `json:"runId"`
	// CredentialID is the non-secret platform credential id the Runtime opens
	// through the Box credential bridge. No secret material is ever carried in
	// the manifest.
	CredentialID string `json:"credentialId"`
	// ProviderID is the non-secret tool provider identifier (for example
	// "github"). It is also the provider id the opened credential must bind.
	ProviderID string `json:"providerId"`
	// ConnectionID is the optional non-secret platform account connection id.
	// When absent the credential id is used as the connection id.
	ConnectionID string `json:"connectionId,omitempty"`
	// Tools is the template-declared tool allowlist the gateway advertises.
	// Exactly these tools become callable for this sandbox; at least one and at
	// most MaxProviderGatewayTools are required.
	Tools []ProviderGatewayTool `json:"tools"`
}

// EffectiveConnectionID returns the non-secret connection id the gateway binds:
// the explicit ConnectionID, or the credential id when it is absent.
func (requirement ProviderGatewayRequirement) EffectiveConnectionID() string {
	if requirement.ConnectionID != "" {
		return requirement.ConnectionID
	}
	return requirement.CredentialID
}

// ProviderGatewayTool is one template-declared provider tool the gateway may
// expose to the sandbox agent.
type ProviderGatewayTool struct {
	// Name is the MCP-safe tool name the agent calls.
	Name string `json:"name"`
	// Description is the bounded tool description shown to the model. It is
	// optional.
	Description string `json:"description,omitempty"`
	// InputSchema is the bounded JSON object schema advertised through
	// tools/list. The gateway does not execute it.
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ValidateProviderGatewayRequirements validates the additive provider gateway
// contract of one sandbox. The zero value (no requirements) is always valid, so
// manifests that never carried the field decode, validate and re-encode exactly
// as before. Every requirement and tool is bounded, every identifier is checked
// against its closed safe grammar, and the manifest can never carry secret
// material because the shape has no such field and unknown fields are rejected
// by the strict decoders.
func ValidateProviderGatewayRequirements(requirements []ProviderGatewayRequirement) error {
	if len(requirements) > MaxProviderGatewaysPerSandbox {
		return fmt.Errorf("at most %d provider gateways are supported", MaxProviderGatewaysPerSandbox)
	}
	seenRuns := make(map[string]struct{}, len(requirements))
	for index := range requirements {
		requirement := &requirements[index]
		if !providerGatewayRunIDPattern.MatchString(requirement.RunID) ||
			len(requirement.RunID) > maxProviderGatewayIdentifierBytes {
			return fmt.Errorf(
				"provider gateway requirement %d has an invalid run id "+
					"(letters, digits, '_' or '-', at most %d bytes)",
				index+1, maxProviderGatewayIdentifierBytes,
			)
		}
		if _, duplicate := seenRuns[requirement.RunID]; duplicate {
			return fmt.Errorf("provider gateway requirement %d has a duplicate run id", index+1)
		}
		seenRuns[requirement.RunID] = struct{}{}
		if !providerGatewayCredentialIDPattern.MatchString(requirement.CredentialID) ||
			len(requirement.CredentialID) > maxProviderGatewayIdentifierBytes {
			return fmt.Errorf("provider gateway requirement %d has an invalid credential id", index+1)
		}
		if !providerGatewayProviderIDPattern.MatchString(requirement.ProviderID) ||
			len(requirement.ProviderID) > maxProviderGatewayIdentifierBytes {
			return fmt.Errorf("provider gateway requirement %d has an invalid provider id", index+1)
		}
		if requirement.ConnectionID != "" &&
			(!providerGatewayCredentialIDPattern.MatchString(requirement.ConnectionID) ||
				len(requirement.ConnectionID) > maxProviderGatewayIdentifierBytes) {
			return fmt.Errorf("provider gateway requirement %d has an invalid connection id", index+1)
		}
		if len(requirement.Tools) == 0 || len(requirement.Tools) > MaxProviderGatewayTools {
			return fmt.Errorf(
				"provider gateway requirement %d must declare between 1 and %d tools",
				index+1, MaxProviderGatewayTools,
			)
		}
		seenTools := make(map[string]struct{}, len(requirement.Tools))
		for toolIndex := range requirement.Tools {
			tool := &requirement.Tools[toolIndex]
			if !providerGatewayToolNamePattern.MatchString(tool.Name) {
				return fmt.Errorf(
					"provider gateway requirement %d tool %d has an invalid name",
					index+1, toolIndex+1,
				)
			}
			if _, duplicate := seenTools[tool.Name]; duplicate {
				return fmt.Errorf(
					"provider gateway requirement %d tool %d has a duplicate name",
					index+1, toolIndex+1,
				)
			}
			seenTools[tool.Name] = struct{}{}
			if len(tool.Description) > MaxProviderGatewayDescriptionBytes ||
				!utf8.ValidString(tool.Description) {
				return fmt.Errorf(
					"provider gateway requirement %d tool %d has an invalid description",
					index+1, toolIndex+1,
				)
			}
			if len(tool.InputSchema) == 0 ||
				len(tool.InputSchema) > MaxProviderGatewayInputSchemaBytes ||
				!providerGatewayJSONObject(tool.InputSchema) {
				return fmt.Errorf(
					"provider gateway requirement %d tool %d has an invalid input schema",
					index+1, toolIndex+1,
				)
			}
		}
	}
	return nil
}

// providerGatewayJSONObject reports whether raw is exactly one JSON object.
func providerGatewayJSONObject(raw json.RawMessage) bool {
	if !json.Valid(raw) {
		return false
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	_, isObject := value.(map[string]any)
	return isObject
}

// SameProviderGatewayRequirements reports whether two requirement lists are
// semantically identical, comparing the embedded input schemas as JSON rather
// than as raw bytes so insignificant whitespace never looks like a change. It
// is used by the reconciler to decide whether a running gateway must be
// replaced.
func SameProviderGatewayRequirements(left, right []ProviderGatewayRequirement) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		leftPayload, err := json.Marshal(left[index])
		if err != nil {
			return false
		}
		rightPayload, err := json.Marshal(right[index])
		if err != nil {
			return false
		}
		if string(leftPayload) != string(rightPayload) {
			return false
		}
	}
	return true
}
