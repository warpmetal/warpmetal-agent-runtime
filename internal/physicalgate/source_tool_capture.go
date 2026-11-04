package physicalgate

import (
	"encoding/base64"
	"encoding/json"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Validate ORIGINAL shell list/get/output bytes and join container PID to the
// independently captured Runtime descendant identity. No shell.remove,404,
// collector "stable" flag or supplied kernel tree substitutes for kernel exits.
func verifySourcePreCancelTool(raw []byte, cut SourceKernelCut, session string) error {
	fields, err := sourceObject(raw)
	if err != nil || string(fields["error"]) != "null" {
		return ErrPrerequisite
	}
	var shells []struct {
		Listed         json.RawMessage `json:"listed"`
		NativeShell    json.RawMessage `json:"nativeShell"`
		NativeOutput   json.RawMessage `json:"nativeOutput"`
		KernelIdentity json.RawMessage `json:"kernelIdentity"`
	}
	if model.DecodePhysicalClosed(fields["shells"], &shells) != nil || len(shells) == 0 || len(shells) > 128 {
		return ErrPrerequisite
	}
	listRaw, err := sourceToolOriginal(fields["nativeShellList"])
	if err != nil {
		return err
	}
	list, err := sourceObject(listRaw)
	if err != nil || len(list) != 2 || list["location"] == nil {
		return ErrPrerequisite
	}
	var all []json.RawMessage
	if model.DecodePhysicalClosed(list["data"], &all) != nil {
		return ErrPrerequisite
	}
	seen := map[string]bool{}
	for _, shell := range shells {
		getRaw, err := sourceToolOriginal(shell.NativeShell)
		if err != nil {
			return err
		}
		get, err := sourceObject(getRaw)
		if err != nil || len(get) != 2 || model.WorkspaceDigest(json.RawMessage(get["location"])) != model.WorkspaceDigest(json.RawMessage(list["location"])) || model.WorkspaceDigest(json.RawMessage(get["data"])) != model.WorkspaceDigest(shell.Listed) {
			return ErrPrerequisite
		}
		meta, err := sourceObject(get["data"])
		if err != nil {
			return err
		}
		var id, status string
		var pid int
		if json.Unmarshal(meta["id"], &id) != nil || !model.PhysicalIDValid(id) || seen[id] || json.Unmarshal(meta["status"], &status) != nil || status != "running" || json.Unmarshal(meta["pid"], &pid) != nil || pid <= 1 {
			return ErrPrerequisite
		}
		metadata, err := sourceObject(meta["metadata"])
		var owning string
		if err != nil || json.Unmarshal(metadata["sessionID"], &owning) != nil || owning != session {
			return ErrPrerequisite
		}
		listed := false
		for _, original := range all {
			if model.WorkspaceDigest(original) == model.WorkspaceDigest(shell.Listed) {
				listed = true
			}
		}
		if !listed {
			return ErrPrerequisite
		}
		registered := false
		for _, child := range cut.Descendants {
			if child.ContainerPID == pid && child.StartTime > 0 {
				registered = true
			}
		}
		if !registered {
			return ErrPrerequisite
		}
		outputRaw, err := sourceToolOriginal(shell.NativeOutput)
		if err != nil {
			return err
		}
		output, err := sourceObject(outputRaw)
		if err != nil || len(output) != 2 || model.WorkspaceDigest(json.RawMessage(output["location"])) != model.WorkspaceDigest(json.RawMessage(list["location"])) {
			return ErrPrerequisite
		}
		body, err := sourceObject(output["data"])
		var cursor, size int64
		var text string
		var truncated bool
		if err != nil || body["truncated"] == nil || json.Unmarshal(body["cursor"], &cursor) != nil || json.Unmarshal(body["size"], &size) != nil || cursor < 0 || cursor != size || json.Unmarshal(body["output"], &text) != nil || json.Unmarshal(body["truncated"], &truncated) != nil || truncated {
			return ErrPrerequisite
		}
		seen[id] = true
	}
	return nil
}

func sourceToolOriginal(raw []byte) ([]byte, error) {
	fields, err := sourceObject(raw)
	var status int
	var encoded string
	if err != nil || len(fields) != 3 || json.Unmarshal(fields["status"], &status) != nil || status != 200 || json.Unmarshal(fields["rawBytes"], &encoded) != nil {
		return nil, ErrPrerequisite
	}
	original, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(original) != encoded {
		return nil, ErrPrerequisite
	}
	if _, err = sourceObject(original); err != nil {
		return nil, err
	}
	if model.WorkspaceDigest(json.RawMessage(original)) != model.WorkspaceDigest(json.RawMessage(fields["body"])) {
		return nil, ErrPrerequisite
	}
	return original, nil
}
