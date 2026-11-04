package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// ReportAck is the ordered acceptance view of one Runtime report (P3/R2).
type ReportAck struct {
	ReportEpoch      int64
	DesiredRevision  int64
	AppliedRevision  int64
	ResyncGeneration int64
	Replayed         bool
}

// ReportSync sends one reconciled report with bounded retry/backoff, ordered
// sequence/digest idempotency and a persisted terminal block (C2a R2).
//
// On a typed 409 the sync re-reads the manifest and retries the report body
// against the CURRENT desired epoch rather than replaying an unappliable body
// forever. After the bounded attempts the block is persisted; a newer manifest
// desired revision (owner redrive/operator resync) clears it automatically, and
// the persisted sequence means a daemon restart cannot duplicate a report body.
type ReportSync struct {
	Post     func(context.Context, model.Report) (ReportAck, error)
	Manifest func(context.Context) (model.Manifest, error)
	// Rebuild re-derives the report body against a freshly re-read manifest when
	// the backend rejects a report as a typed reconciliation conflict. An owner
	// setup redrive supersedes the failed operation and creates a new immutable
	// setup generation with a bumped desired revision; the in-flight report body
	// still carries the superseded tuple, so replaying the same bytes can never
	// be accepted. Rebuild lets the caller reconcile the fresh manifest (adopt
	// the new setup operation generation) and hand back the current report body
	// instead of spinning until the bounded block. It is bounded by MaxRebuilds
	// per Send and by the existing attempt/window bounds; it never widens what
	// the backend accepts.
	Rebuild func(context.Context, model.Manifest) (*model.Report, error)
	Store   *state.Store
	Sleep   func(context.Context, time.Duration) bool
	Jitter  func() float64
	Now     func() time.Time
	Rand    func() float64

	MaxAttempts int
	// MaxRebuilds bounds fresh-manifest report rebuilds inside one Send. The
	// ordinary attempt/window bounds still apply; zero selects the default.
	MaxRebuilds int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	MaxWindow   time.Duration
}

const (
	reportSyncDefaultAttempts = 12
	reportSyncDefaultRebuilds = 3
	reportSyncBaseDelay       = 250 * time.Millisecond
	reportSyncMaxDelay        = 8 * time.Second
	reportSyncMaxWindow       = 5 * time.Minute
)

func (r *ReportSync) defaults() {
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = reportSyncDefaultAttempts
	}
	if r.MaxRebuilds <= 0 {
		r.MaxRebuilds = reportSyncDefaultRebuilds
	}
	if r.BaseDelay <= 0 {
		r.BaseDelay = reportSyncBaseDelay
	}
	if r.MaxDelay <= 0 {
		r.MaxDelay = reportSyncMaxDelay
	}
	if r.MaxWindow <= 0 {
		r.MaxWindow = reportSyncMaxWindow
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Sleep == nil {
		r.Sleep = func(ctx context.Context, d time.Duration) bool {
			if d <= 0 {
				return true
			}
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-timer.C:
				return true
			}
		}
	}
	if r.Rand == nil {
		r.Rand = func() float64 { return 0.5 }
	}
}

func reportDigest(report model.Report) (string, error) {
	body := report
	body.ReportDigest = ""
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func rejection(err error) (*api.ResponseError, bool) {
	var response *api.ResponseError
	if errors.As(err, &response) && response.Status == 409 {
		switch response.Code {
		case "runtime_report_conflict", "runtime_report_stale":
			return response, true
		}
	}
	return nil, false
}

func detailInt(detail map[string]any, key string) int64 {
	if detail == nil {
		return 0
	}
	switch value := detail[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	}
	return 0
}

// Send posts the report once, retrying only on the typed reconciliation 409s and
// transient errors. It returns nil both on acceptance and after a persisted
// terminal block: a blocked report never kills the daemon loop and never spins.
func (r *ReportSync) Send(ctx context.Context, report *model.Report) error {
	if r == nil || r.Post == nil || r.Store == nil || report == nil {
		return errors.New("report sync is not configured")
	}
	r.defaults()
	blocked, err := r.Store.ReportSyncState(ctx)
	if err != nil {
		return fmt.Errorf("load report sync state: %w", err)
	}
	sequence := blocked.Sequence
	var manifest model.Manifest
	if blocked.BlockedCode != "" {
		manifest, err = r.Manifest(ctx)
		if err != nil {
			return fmt.Errorf("fetch manifest for report block recovery: %w", err)
		}
		if manifest.DesiredRevision <= blocked.BlockedDesiredRevision {
			// Still blocked: the desired epoch has not moved. No retry/spin.
			return nil
		}
		blocked.BlockedCode, blocked.BlockedDetail, blocked.BlockedSince = "", "", ""
		blocked.BlockedDesiredRevision, blocked.BlockedResyncGeneration = 0, 0
		if err := r.Store.PutReportSyncState(ctx, blocked); err != nil {
			return fmt.Errorf("clear report block: %w", err)
		}
	}
	started := r.Now()
	attempt := 0
	rebuilds := 0
	lastCode, lastDetail := "", ""
	var observedDesired int64
	for attempt < r.MaxAttempts {
		if r.Now().Sub(started) > r.MaxWindow {
			break
		}
		attempt++
		sequence++
		report.ReportSequence = sequence
		report.ObservedDesiredRevision = observedDesired
		digest, digestErr := reportDigest(*report)
		if digestErr != nil {
			return digestErr
		}
		report.ReportDigest = digest
		ack, sendErr := r.Post(ctx, *report)
		if sendErr == nil {
			blocked.Sequence = sequence
			blocked.LastEpoch = ack.ReportEpoch
			blocked.BlockedCode, blocked.BlockedDetail, blocked.BlockedSince = "", "", ""
			blocked.BlockedDesiredRevision, blocked.BlockedResyncGeneration = 0, 0
			return r.Store.PutReportSyncState(ctx, blocked)
		}
		response, reconcilable := rejection(sendErr)
		if !reconcilable {
			lastCode, lastDetail = "", ""
			if err := r.backoff(ctx, attempt, started); err != nil {
				return err
			}
			continue
		}
		lastCode = response.Code
		lastDetail = response.Error()
		manifest, manifestErr := r.Manifest(ctx)
		if manifestErr != nil {
			if err := r.backoff(ctx, attempt, started); err != nil {
				return err
			}
			continue
		}
		observedDesired = manifest.DesiredRevision
		// A superseded setup generation (owner redrive) keeps the desired revision
		// but replaces the operation tuple the report must carry: re-derive the
		// report body from the freshly read manifest so the next attempt is
		// applicable instead of replaying stale bytes.
		if r.Rebuild != nil && rebuilds < r.MaxRebuilds {
			rebuilds++
			if rebuilt, rebuildErr := r.Rebuild(ctx, manifest); rebuildErr == nil && rebuilt != nil {
				report = rebuilt
				report.ReportSequence = sequence
				report.ObservedDesiredRevision = manifest.DesiredRevision
				if err := r.backoff(ctx, attempt, started); err != nil {
					return err
				}
				continue
			}
		}
		// A newer resync generation means the backend deliberately moved the
		// desired epoch: retry promptly with the fresh body instead of spending
		// the remaining attempts on an obsolete report.
		if generation := detailInt(response.Detail, "resyncGeneration"); generation >
			blocked.BlockedResyncGeneration {
			blocked.BlockedResyncGeneration = generation
			attempt = 0
		}
		if err := r.backoff(ctx, attempt, started); err != nil {
			return err
		}
	}
	// Bounded exhaustion: persist a typed terminal block; the daemon loop keeps
	// running (no crash) and only a newer manifest desired revision clears it.
	blocked.Sequence = sequence
	if lastCode == "" {
		lastCode = "report_retry_exhausted"
	}
	blocked.BlockedCode = lastCode
	blocked.BlockedDetail = lastDetail
	blocked.BlockedSince = r.Now().UTC().Format(time.RFC3339)
	blocked.BlockedDesiredRevision = observedDesired
	return r.Store.PutReportSyncState(ctx, blocked)
}

func (r *ReportSync) backoff(ctx context.Context, attempt int, started time.Time) error {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Duration(float64(r.BaseDelay) * math.Pow(2, float64(attempt-1)))
	if delay > r.MaxDelay {
		delay = r.MaxDelay
	}
	delay = time.Duration(float64(delay) * (1 + 0.2*(r.Rand()-0.5)*2))
	remaining := r.MaxWindow - r.Now().Sub(started)
	if remaining <= 0 {
		return nil
	}
	if delay > remaining {
		delay = remaining
	}
	if !r.Sleep(ctx, delay) {
		return ctx.Err()
	}
	return nil
}
