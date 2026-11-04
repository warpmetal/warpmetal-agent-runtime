package model

import (
	"errors"
	"reflect"
	"time"
)

// Current identity/quiescence of an already consumed execution. It carries no
// artifact path, declared success, policy, caller clock or execution permission.
type ChildCompletedCapture struct {
	FormatVersion   int                  `json:"formatVersion"`
	Purpose         string               `json:"purpose"`
	Session         ChildNativeSession   `json:"session"`
	PreparedReceipt PreparedReceipt      `json:"preparedReceipt"`
	Grant           CellExecutionGrantV3 `json:"grant"`
	Native          ChildNativeExecution `json:"native"`
	DatabaseDevice  uint64               `json:"databaseDevice"`
	DatabaseInode   uint64               `json:"databaseInode"`
	ObservedAt      string               `json:"observedAt"`
}

func (c ChildCompletedCapture) ValidateFor(e CellServiceV3, receipt PreparedReceipt, parent, directory string, now time.Time) error {
	bad := errors.New("completed child native identity conflict")
	n := c.Native
	when, err := time.Parse(time.RFC3339Nano, c.ObservedAt)
	if err != nil || when.After(now) || now.Sub(when) > 30*time.Second || c.FormatVersion != 1 || c.Purpose != "child_completed_state" || c.DatabaseDevice == 0 || c.DatabaseInode == 0 ||
		!ValidCellNativeSessionID(parent) || directory == "" || (e.Role != "worker" && e.Role != "reviewer") || e.DesiredState != "active" || e.Authority == nil || e.Authority.ModelID == nil || e.ExecutionGrant == nil || e.PreparedReceiptDigest == nil ||
		c.Session.ID != e.NativeSessionID || c.Session.ProjectID != e.NativeProjectID || c.Session.ParentID != parent || c.Session.Directory != directory || c.Session.ForkSessionID != nil || c.Session.WorkspaceID != nil || c.Session.Agent != "warpmetal-managed" ||
		c.Session.Model.ProviderID != e.Authority.ProviderID || c.Session.Model.ID != *e.Authority.ModelID || (c.Session.Model.Variant != "" && c.Session.Model.Variant != "default") ||
		e.ValidateExecutionAuthority(receipt) != nil || c.PreparedReceipt.ValidateFor(e) != nil || !reflect.DeepEqual(c.PreparedReceipt, receipt) || !reflect.DeepEqual(c.Grant, *e.ExecutionGrant) ||
		n.SessionID != e.NativeSessionID || n.NativeProjectID != e.NativeProjectID || n.NativeLocationDigest != WorkspaceDigest(map[string]any{"directory": directory, "projectId": e.NativeProjectID, "workspaceId": nil}) || n.InputID != c.Grant.InputID || n.PreparedReceiptDigest != *e.PreparedReceiptDigest || n.GrantDigest != WorkspaceDigest(c.Grant) ||
		!PhysicalDigestValid(n.InputDigest) || !PhysicalIDValid(n.AssistantMessageID) || n.EnqueueSeq < 1 || n.InitialExecutionStartedSeq <= n.EnqueueSeq || n.LogCursor > 32768 || !n.Current.Quiescent(n.InitialExecutionStartedSeq, n.TerminalSeq, n.LogCursor) {
		return bad
	}
	// Expiry of the already consumed grant is history. The new facts operation
	// and independently current native state authorize this read-only observation.
	return nil
}
