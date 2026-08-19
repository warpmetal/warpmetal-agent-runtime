package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type Workspaces interface {
	Ensure(context.Context, string, int) (string, error)
	Destroy(context.Context, string) error
}

type Sessions interface {
	TerminateGrant(context.Context, string) error
	TerminateSandbox(context.Context, string) error
}

type Reconciler struct {
	Store        *state.Store
	Engine       containers.Engine
	Workspaces   Workspaces
	Access       access.Renderer
	Sessions     Sessions
	HostCapacity model.Resources
	ServerID     string
	Now          func() time.Time
}

func (r *Reconciler) Reconcile(ctx context.Context, manifest model.Manifest) error {
	lastRevision, err := r.Store.Revision(ctx)
	if err != nil {
		return err
	}
	if err := model.ValidateManifest(manifest, r.ServerID, lastRevision); err != nil {
		return err
	}
	if !requested(manifest.Sandboxes).Fits(r.HostCapacity) {
		return errors.New("desired sandboxes exceed detected host capacity")
	}
	for _, desired := range manifest.Sandboxes {
		if err := r.reconcileSandbox(ctx, desired, manifest.ImageDigest); err != nil {
			return fmt.Errorf("reconcile sandbox %s: %w", desired.ID, err)
		}
	}
	if err := r.reconcileMissingSandboxes(ctx, manifest.Sandboxes); err != nil {
		return err
	}
	if err := r.reconcileGrants(ctx, manifest.AccessGrants); err != nil {
		return err
	}
	return r.Store.SetRevision(ctx, manifest.DesiredRevision)
}

func (r *Reconciler) reconcileMissingSandboxes(
	ctx context.Context,
	desired []model.Sandbox,
) error {
	desiredIDs := make(map[string]bool, len(desired))
	for _, sandbox := range desired {
		desiredIDs[sandbox.ID] = true
	}
	current, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return err
	}
	for index := range current {
		local := &current[index]
		if desiredIDs[local.ID] {
			continue
		}
		if local.ObservedState != "deleted" {
			local.DesiredState = "deleted"
			if err := r.removeSandbox(ctx, local); err != nil {
				return fmt.Errorf("remove omitted sandbox %s: %w", local.ID, err)
			}
		}
		if err := r.Store.DeleteSandbox(ctx, local.ID); err != nil {
			return fmt.Errorf("prune sandbox tombstone %s: %w", local.ID, err)
		}
	}
	return nil
}

func (r *Reconciler) Expire(ctx context.Context) error {
	values, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return err
	}
	current := r.now()
	for index := range values {
		value := &values[index]
		if value.Lifetime == "temporary" && value.ExpiresAt != nil &&
			!current.Before(*value.ExpiresAt) && value.ObservedState != "deleted" {
			value.DesiredState = "deleted"
			if err := r.removeSandbox(ctx, value); err != nil {
				return fmt.Errorf("expire sandbox %s: %w", value.ID, err)
			}
		}
	}
	return nil
}

func (r *Reconciler) Report(ctx context.Context, serverID, version string) (model.Report, error) {
	revision, err := r.Store.Revision(ctx)
	if err != nil {
		return model.Report{}, err
	}
	sandboxes, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return model.Report{}, err
	}
	grants, err := r.Store.Grants(ctx)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{
		ServerID:          serverID,
		AppliedRevision:   revision,
		SupervisorVersion: version,
	}
	for _, value := range sandboxes {
		item := model.SandboxReport{
			ID:                 value.ID,
			ObservedState:      value.ObservedState,
			ObservedGeneration: value.ObservedGeneration,
			ImageDigest:        value.ImageDigest,
			StartedAt:          value.StartedAt,
			ExpiresAt:          value.ExpiresAt,
		}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.Sandboxes = append(report.Sandboxes, item)
	}
	for _, value := range grants {
		item := model.GrantReport{ID: value.ID, ObservedState: value.ObservedState}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.AccessGrants = append(report.AccessGrants, item)
	}
	return report, nil
}

func (r *Reconciler) reconcileSandbox(
	ctx context.Context,
	desired model.Sandbox,
	imageDigest string,
) error {
	local, err := r.Store.Sandbox(ctx, desired.ID)
	if err != nil {
		return err
	}
	if local == nil {
		local = &state.LocalSandbox{
			ID:                 desired.ID,
			Name:               desired.Name,
			ObservedState:      "pending",
			ObservedGeneration: 0,
		}
	}
	local.Name = desired.Name
	local.DesiredState = desired.DesiredState
	local.Generation = desired.Generation
	local.Lifetime = desired.Lifetime
	local.ExpiresInSeconds = desired.ExpiresInSeconds
	local.Resources = desired.Resources
	// Pin a sandbox to the image used when it was first created. A new default
	// applies only to new sandboxes; existing workspaces are never disrupted by
	// an implicit image replacement.
	if local.ImageDigest == "" {
		local.ImageDigest = imageDigest
	}
	if local.StartedAt == nil && desired.StartedAt != nil {
		local.StartedAt = desired.StartedAt
	}
	if local.ExpiresAt == nil && desired.ExpiresAt != nil {
		local.ExpiresAt = desired.ExpiresAt
	}
	if local.Lifetime == "persistent" {
		local.ExpiresInSeconds = nil
		local.ExpiresAt = nil
	}
	if local.Lifetime == "temporary" && local.ExpiresAt != nil &&
		!r.now().Before(*local.ExpiresAt) {
		local.DesiredState = "deleted"
	}
	if err := r.Store.PutSandbox(ctx, *local); err != nil {
		return err
	}
	switch local.DesiredState {
	case "deleted":
		return r.removeSandbox(ctx, local)
	case "stopped":
		if local.ObservedState != "stopped" {
			local.ObservedState = "stopping"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
		}
		if r.Sessions != nil {
			_ = r.Sessions.TerminateSandbox(ctx, local.ID)
		}
		if err := r.Engine.Stop(ctx, local.ID); err != nil {
			return r.failSandbox(ctx, local, "container_stop_failed", err)
		}
		local.ObservedState = "stopped"
		local.ObservedGeneration = local.Generation
		return r.Store.PutSandbox(ctx, *local)
	case "running":
		if local.ObservedState == "deleted" && local.Lifetime == "temporary" {
			return nil
		}
		workspace, err := r.Workspaces.Ensure(ctx, local.ID, local.Resources.WorkspaceDiskGiB)
		if err != nil {
			return r.failSandbox(ctx, local, "workspace_create_failed", err)
		}
		if local.ObservedState == "running" && local.ObservedGeneration < local.Generation {
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Restart(ctx, local.ID); err != nil {
				return r.failSandbox(ctx, local, "container_restart_failed", err)
			}
		} else if local.ObservedState == "stopped" {
			if err := r.Engine.Start(ctx, local.ID); err != nil {
				return r.failSandbox(ctx, local, "container_start_failed", err)
			}
		} else if local.ObservedState == "running" {
			if err := r.Engine.Ensure(ctx, desired, workspace, local.ImageDigest); err != nil {
				return r.failSandbox(ctx, local, "container_reconcile_failed", err)
			}
		} else if local.ObservedState != "running" {
			local.ObservedState = "creating"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			desired.ExpiresAt = local.ExpiresAt
			if err := r.Engine.Ensure(ctx, desired, workspace, local.ImageDigest); err != nil {
				return r.failSandbox(ctx, local, "container_create_failed", err)
			}
		}
		started := r.now()
		if local.StartedAt == nil {
			local.StartedAt = &started
			if local.Lifetime == "temporary" && local.ExpiresInSeconds != nil {
				expires := started.Add(time.Duration(*local.ExpiresInSeconds) * time.Second)
				local.ExpiresAt = &expires
			}
		}
		local.ObservedState = "running"
		local.ObservedGeneration = local.Generation
		local.ErrorCode = ""
		local.ErrorMessage = ""
		return r.Store.PutSandbox(ctx, *local)
	default:
		return errors.New("unsupported desired state")
	}
}

func (r *Reconciler) removeSandbox(ctx context.Context, local *state.LocalSandbox) error {
	if local.ObservedState == "deleted" {
		return nil
	}
	local.ObservedState = "deleting"
	if err := r.Store.PutSandbox(ctx, *local); err != nil {
		return err
	}
	if r.Sessions != nil {
		_ = r.Sessions.TerminateSandbox(ctx, local.ID)
	}
	if err := r.Engine.Remove(ctx, local.ID); err != nil {
		return r.failSandbox(ctx, local, "container_delete_failed", err)
	}
	if err := r.Workspaces.Destroy(ctx, local.ID); err != nil {
		return r.failSandbox(ctx, local, "workspace_delete_failed", err)
	}
	local.ObservedState = "deleted"
	local.ObservedGeneration = local.Generation
	local.ErrorCode = ""
	local.ErrorMessage = ""
	return r.Store.PutSandbox(ctx, *local)
}

func (r *Reconciler) failSandbox(
	ctx context.Context,
	local *state.LocalSandbox,
	code string,
	err error,
) error {
	local.ObservedState = "failed"
	local.ErrorCode = code
	local.ErrorMessage = bounded(err.Error(), 300)
	if saveErr := r.Store.PutSandbox(ctx, *local); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	return err
}

func (r *Reconciler) reconcileGrants(ctx context.Context, desired []model.AccessGrant) error {
	existing, err := r.Store.Grants(ctx)
	if err != nil {
		return err
	}
	desiredIDs := map[string]bool{}
	for _, grant := range desired {
		desiredIDs[grant.ID] = true
		value := state.LocalGrant{
			ID:            grant.ID,
			SandboxID:     grant.SandboxID,
			SSHPublicKey:  grant.SSHPublicKey,
			DesiredState:  grant.DesiredState,
			ObservedState: "pending",
		}
		for _, current := range existing {
			if current.ID == grant.ID {
				value.ObservedState = current.ObservedState
			}
		}
		if grant.DesiredState == "revoked" {
			value.ObservedState = "revoking"
			if r.Sessions != nil {
				if err := r.Sessions.TerminateGrant(ctx, grant.ID); err != nil {
					return err
				}
			}
		}
		if err := r.Store.PutGrant(ctx, value); err != nil {
			return err
		}
	}
	for _, current := range existing {
		if !desiredIDs[current.ID] && current.DesiredState == "active" {
			current.DesiredState = "revoked"
			current.ObservedState = "revoking"
			if r.Sessions != nil {
				if err := r.Sessions.TerminateGrant(ctx, current.ID); err != nil {
					return err
				}
			}
			if err := r.Store.PutGrant(ctx, current); err != nil {
				return err
			}
		}
	}
	all, err := r.Store.Grants(ctx)
	if err != nil {
		return err
	}
	if err := r.Access.Write(all); err != nil {
		for index := range all {
			if all[index].DesiredState == "active" {
				all[index].ObservedState = "failed"
				all[index].ErrorCode = "access_mapping_failed"
				all[index].ErrorMessage = bounded(err.Error(), 300)
				_ = r.Store.PutGrant(ctx, all[index])
			}
		}
		return err
	}
	for index := range all {
		if all[index].DesiredState == "active" {
			all[index].ObservedState = "applied"
		} else {
			all[index].ObservedState = "revoked"
		}
		all[index].ErrorCode = ""
		all[index].ErrorMessage = ""
		if err := r.Store.PutGrant(ctx, all[index]); err != nil {
			return err
		}
		if !desiredIDs[all[index].ID] && all[index].DesiredState == "revoked" {
			if err := r.Store.DeleteGrant(ctx, all[index].ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func requested(sandboxes []model.Sandbox) model.Resources {
	value := model.Resources{}
	for _, sandbox := range sandboxes {
		if sandbox.DesiredState == "deleted" {
			continue
		}
		value.WorkspaceDiskGiB += sandbox.Resources.WorkspaceDiskGiB
		if sandbox.DesiredState == "running" {
			value.CPUMillicores += sandbox.Resources.CPUMillicores
			value.MemoryMiB += sandbox.Resources.MemoryMiB
		}
	}
	return value
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
