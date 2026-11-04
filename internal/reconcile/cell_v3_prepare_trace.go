package reconcile

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
)

// Bounded formatVersion 3 preparation diagnostics (R-WP120-1).
//
// A blocked V3 preparation persisted only its stage token (for example
// credential_lease). That names the predicate that refused the managed child,
// but not WHICH sub-step, timeout or response class produced it: the idempotent
// credential fetch retries, the per-request control-plane client timeout, the
// trusted-adapter child launch and the manager-instance readiness are all
// indistinguishable from the durable row alone.
//
// cellV3PrepareTrace adds one bounded log line per step of a SINGLE prepare
// pass. It carries only:
//   - the preparation id (an already durable public identity),
//   - a closed step name from this file,
//   - wall-clock elapsed time and a bounded attempt counter,
//   - a closed cause token derived from the error CLASS and HTTP status/code.
//
// It never carries a prompt, credential material, a receipt, a response body,
// a supervisor diagnostic or any free-text error string, so it is safe to keep
// enabled in production and safe to ship in evidence.
const (
	cellV3TraceMaxSteps = 24
	cellV3TraceMaxToken = 48
)

type cellV3PrepareTrace struct {
	preparationID string
	started       time.Time
	last          time.Time
	steps         []string
}

func newCellV3PrepareTrace(preparationID string) *cellV3PrepareTrace {
	now := time.Now()
	return &cellV3PrepareTrace{preparationID: preparationID, started: now, last: now}
}

// step records and logs one completed step of the current pass.
func (t *cellV3PrepareTrace) step(name string) {
	if t == nil {
		return
	}
	now := time.Now()
	delta, total := now.Sub(t.last), now.Sub(t.started)
	t.last = now
	if len(t.steps) < cellV3TraceMaxSteps {
		t.steps = append(t.steps, name)
	}
	log.Printf("cell v3 prepare %s step=%s delta=%s total=%s",
		t.preparationID, cellV3TraceToken(name, cellV3TraceMaxToken),
		delta.Round(time.Millisecond), total.Round(time.Millisecond))
}

// note logs one free-form, bounded diagnostic line attached to the trace. The
// message must already be built from closed tokens only.
func (t *cellV3PrepareTrace) note(format string, arguments ...any) {
	if t == nil {
		return
	}
	log.Printf("cell v3 prepare %s "+format+" total=%s",
		append([]any{t.preparationID}, append(arguments, t.total().Round(time.Millisecond))...)...)
}

func (t *cellV3PrepareTrace) total() time.Duration {
	if t == nil {
		return 0
	}
	return time.Since(t.started)
}

// trail is the bounded list of steps reached in this pass, joined for the single
// "child not created" line so one log line names the whole path.
func (t *cellV3PrepareTrace) trail() string {
	if t == nil || len(t.steps) == 0 {
		return "none"
	}
	return strings.Join(t.steps, ",")
}

// cellV3TraceToken keeps only [a-z0-9_.:-] and bounds the length, so a step name
// or a closed reason can never smuggle free text into the log.
func cellV3TraceToken(value string, maximum int) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '_', character == '.', character == '-', character == ':':
			builder.WriteRune(character)
		}
		if builder.Len() >= maximum {
			break
		}
	}
	return builder.String()
}

// cellV3CauseToken reduces an error to a closed, bounded token that names the
// CLASS of failure without any payload: a context outcome, an HTTP status plus
// the backend's bounded error code, a transport timeout, the managed
// supervisor's closed reason token, or the generic "error".
func cellV3CauseToken(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var response *api.ResponseError
	if errors.As(err, &response) {
		if code := managedSupervisorToken(response.Code); code != "" {
			return "http_" + strconv.Itoa(response.Status) + ":" + code
		}
		return "http_" + strconv.Itoa(response.Status)
	}
	var failure *managedSupervisorActionFailure
	if errors.As(err, &failure) {
		if reason := failure.reasonToken(); reason != "" {
			return "supervisor:" + reason
		}
		return "supervisor"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "transport_timeout"
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return "transport"
	}
	return "error"
}
