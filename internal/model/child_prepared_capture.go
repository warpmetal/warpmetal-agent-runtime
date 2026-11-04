package model

import (
	"errors"
	"reflect"
	"time"
)

// ChildNativeSession is the fixed native session readback shared by identity
// observations. It carries no execution authority.
type ChildNativeSession struct {
	ID            string  `json:"id"`
	ProjectID     string  `json:"projectId"`
	ParentID      string  `json:"parentId"`
	ForkSessionID *string `json:"forkSessionId"`
	Directory     string  `json:"directory"`
	WorkspaceID   *string `json:"workspaceId"`
	Agent         string  `json:"agent"`
	Model         struct {
		ProviderID string `json:"providerID"`
		ID         string `json:"id"`
		Variant    string `json:"variant,omitempty"`
	} `json:"model"`
}

// Private fixed readback, never a grant or completion. The Supervisor owns the
// coherent no-input/no-start DATA check; Runtime joins the actual native fields
// to its current signed execution and original prepared receipt.
type ChildPreparedCapture struct {
	FormatVersion   int                `json:"formatVersion"`
	Purpose         string             `json:"purpose"`
	Session         ChildNativeSession `json:"session"`
	PreparedReceipt PreparedReceipt    `json:"preparedReceipt"`
	EventCursor     int64              `json:"eventCursor"`
	DatabaseDevice  uint64             `json:"databaseDevice"`
	DatabaseInode   uint64             `json:"databaseInode"`
	ObservedAt      string             `json:"observedAt"`
}

func (c ChildPreparedCapture) ValidateFor(e CellServiceV3, receipt PreparedReceipt, parent, directory string, now time.Time) error {
	bad := errors.New("prepared child native identity conflict")
	when, err := time.Parse(time.RFC3339Nano, c.ObservedAt)
	if err != nil || when.After(now) || now.Sub(when) > 30*time.Second || c.FormatVersion != 1 || c.Purpose != "child_prepared_identity" || c.DatabaseDevice == 0 || c.DatabaseInode == 0 || c.EventCursor < 0 || c.EventCursor > 32768 ||
		!ValidCellNativeSessionID(parent) || directory == "" || e.Role != "reviewer" || e.DesiredState != "active" || e.Authority == nil || e.Authority.ModelID == nil ||
		c.Session.ID != e.NativeSessionID || c.Session.ProjectID != e.NativeProjectID || c.Session.ParentID != parent || c.Session.Directory != directory || c.Session.ForkSessionID != nil || c.Session.WorkspaceID != nil || c.Session.Agent != "warpmetal-managed" ||
		c.Session.Model.ProviderID != e.Authority.ProviderID || c.Session.Model.ID != *e.Authority.ModelID || (c.Session.Model.Variant != "" && c.Session.Model.Variant != "default") ||
		e.ValidateExecutionAuthority(receipt) != nil || c.PreparedReceipt.ValidateFor(e) != nil || !reflect.DeepEqual(c.PreparedReceipt, receipt) {
		return bad
	}
	expires, err := time.Parse(time.RFC3339Nano, e.ExecutionGrant.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return bad
	}
	return nil
}
