package physicalgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// These receipts belong to THIS accepting/writing/closing listener. They cannot
// be supplied by an HTTP client, plugin ACK, PID selector or capture journal.
type SourceExchange struct {
	OperationID, WindowDigest, RequestDigest, AuthorizationSHA256 string
	Method, Path, ContentType                                     string
	RequestBody, ResponsePrefix                                   []byte
	AcceptedAt, BodyReadAt, PrefixAt, ClosedAt                    time.Time
	LocalAddress, RemoteAddress                                   string
	CloseCause                                                    string
	CloseSucceeded                                                bool
	Error                                                         string
}
type sourceExchangeSlot struct {
	exchange    SourceExchange
	prefix      []byte
	done        chan struct{}
	ready       chan struct{}
	prefixReady bool
	claimed     bool
	attempts    int
	err         error
}
type SourceListener struct {
	store *state.Store
	mu    sync.Mutex
	slots map[string]*sourceExchangeSlot
}

func NewSourceListener(store *state.Store) *SourceListener {
	return &SourceListener{store: store, slots: map[string]*sourceExchangeSlot{}}
}

// Private SOURCE fixture owner enrollment after actual SQLite admission. Digest
// and prefix must come from the independently verified fixture, not the request.
// Enrollment neither admits nor creates a listener/financial hold/key/authority.
func (l *SourceListener) Expect(ctx context.Context, id, authorizationSHA256 string, prefix []byte) error {
	if l == nil || l.store == nil || !model.PhysicalDigestValid(authorizationSHA256) || len(prefix) == 0 || len(prefix) > 32768 {
		return ErrPrerequisite
	}
	o, err := l.store.PhysicalOperation(ctx, id)
	if err != nil || o == nil || o.Permit.Offline == nil || o.Phase != "unknown" {
		return ErrPrerequisite
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if first := l.slots[id]; first != nil {
		if first.exchange.AuthorizationSHA256 != authorizationSHA256 || !bytes.Equal(first.prefix, prefix) {
			return ErrPrerequisite
		}
		return nil
	}
	// A restarted owner cannot replay a delivery whose owning socket is gone.
	prior, err := l.store.PhysicalFact(ctx, sourceListenerKey(id))
	if err != nil || prior != nil {
		return ErrPrerequisite
	}
	l.slots[id] = &sourceExchangeSlot{exchange: SourceExchange{OperationID: id, WindowDigest: o.Permit.Offline.WindowDigest, RequestDigest: o.Permit.Request.RequestDigest, AuthorizationSHA256: authorizationSHA256}, prefix: append([]byte(nil), prefix...), done: make(chan struct{}), ready: make(chan struct{})}
	return nil
}

func sourceListenerKey(id string) string {
	return "source_listener_" + model.RawPhysicalDigest([]byte(id))[7:]
}

// Keep the two exact bounded byte originals separately in the existing archive.
// Embedding both as Base64 in a receipt would exceed the unchanged65KiB fact cap.
func sourceSocketOriginal(x SourceExchange) []byte {
	request, prefix := model.RawPhysicalDigest(x.RequestBody), model.RawPhysicalDigest(x.ResponsePrefix)
	x.RequestBody = nil
	x.ResponsePrefix = nil
	raw, _ := json.Marshal(struct {
		Exchange                                SourceExchange
		RequestBodyDigest, ResponsePrefixDigest string
	}{x, request, prefix})
	return raw
}

// The fixed SOURCE final endpoint only. No proxy, arbitrary method/path, public
// physical action or model-selected fixture. net/http owns original request body
// decoding; hijack transfers the actual TLS connection to this listener so EOF /
// reset and Close are observed here rather than inferred from a response hook.
func (l *SourceListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deny := func() { w.WriteHeader(http.StatusForbidden) }
	if l == nil || l.store == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.Method != "POST" || r.URL.Path != "/v1/responses" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 1 {
		deny()
		return
	}
	o, err := l.store.PhysicalOwner(r.Context())
	if err != nil || o == nil || o.Permit.Offline == nil || o.Phase != "unknown" {
		deny()
		return
	}
	l.mu.Lock()
	slot := l.slots[o.OperationID]
	if slot == nil {
		l.mu.Unlock()
		deny()
		return
	}
	slot.attempts++
	if slot.claimed || slot.attempts != 1 {
		slot.err = ErrPrerequisite
		l.mu.Unlock()
		_ = l.store.RetainPhysicalFact(context.WithoutCancel(r.Context()), sourceListenerKey(o.OperationID)+"_duplicate", []byte(`{"classification":"duplicate_delivery","releaseAuthorized":false}`))
		deny()
		return
	}
	slot.claimed = true
	l.mu.Unlock()
	observed := slot.exchange
	observed.AcceptedAt = time.Now().UTC()
	observed.Method = r.Method
	observed.Path = r.URL.Path
	observed.ContentType = r.Header.Get("Content-Type")
	finish := func(e error) {
		if e != nil {
			observed.Error = "owning_transport_incomplete"
		}
		for _, original := range [][]byte{observed.RequestBody, observed.ResponsePrefix} {
			if len(original) > 0 {
				digest := model.RawPhysicalDigest(original)
				if l.store.RetainPhysicalFact(context.WithoutCancel(r.Context()), "source_original_"+digest[7:], original) != nil {
					e = ErrPrerequisite
				}
			}
		}
		raw := sourceSocketOriginal(observed)
		if l.store.RetainPhysicalFact(context.WithoutCancel(r.Context()), sourceListenerKey(o.OperationID)+"_receipt", raw) != nil {
			e = ErrPrerequisite
		}
		l.mu.Lock()
		slot.exchange = observed
		if e != nil {
			slot.err = e
		}
		if !slot.prefixReady {
			slot.prefixReady = true
			close(slot.ready)
		}
		close(slot.done)
		l.mu.Unlock()
	}
	if l.store.RetainPhysicalFact(r.Context(), sourceListenerKey(o.OperationID), []byte(`{"classification":"owning_delivery_started","releaseAuthorized":false}`)) != nil {
		finish(ErrPrerequisite)
		deny()
		return
	}
	if err = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		finish(ErrPrerequisite)
		deny()
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32769))
	r.Body.Close()
	observed.BodyReadAt = time.Now().UTC()
	observed.RequestBody = append([]byte(nil), body...)
	if err != nil || len(body) > 32768 || model.RawPhysicalDigest(body) != slot.exchange.RequestDigest || model.RawPhysicalDigest([]byte(r.Header.Get("Authorization"))) != slot.exchange.AuthorizationSHA256 {
		finish(ErrPrerequisite)
		deny()
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		finish(ErrPrerequisite)
		deny()
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		finish(ErrPrerequisite)
		return
	}
	observed.Method = r.Method
	observed.Path = r.URL.Path
	observed.ContentType = r.Header.Get("Content-Type")
	observed.RequestBody = append([]byte(nil), body...)
	observed.LocalAddress = conn.LocalAddr().String()
	observed.RemoteAddress = conn.RemoteAddr().String()
	// A bounded socket wait is a timeout/UNKNOWN, NEVER successful cancellation.
	err = conn.SetDeadline(time.Now().Add(120 * time.Second))
	if err == nil {
		_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
	}
	if err == nil {
		n, e := conn.Write(slot.prefix)
		observed.ResponsePrefix = append([]byte(nil), slot.prefix[:n]...)
		observed.PrefixAt = time.Now().UTC()
		err = e
		if n != len(slot.prefix) {
			err = ErrPrerequisite
		}
		l.mu.Lock()
		slot.exchange = observed
		slot.prefixReady = true
		close(slot.ready)
		l.mu.Unlock()
	}
	if err == nil {
		if o.Permit.Offline.Slot.Oracle == "tool_cancel" {
			// Complete tool response ownership is different from an interrupted
			// stalled HTTP response. Native/tool/kernel/late-effect joins remain.
			observed.CloseCause = "response_complete"
		} else {
			_, e := buffer.ReadByte()
			if errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) || errors.Is(e, syscall.ECONNRESET) {
				observed.CloseCause = "peer_closed"
			} else {
				err = ErrPrerequisite
			}
		}
	}
	closeErr := conn.Close()
	observed.ClosedAt = time.Now().UTC()
	observed.CloseSucceeded = closeErr == nil
	if closeErr != nil {
		err = ErrPrerequisite
	}
	finish(err)
}

// Owning accepted-connection snapshot while the prefix is still stalled. This
// lets Runtime join the native fd/inode/net-table tuple BEFORE cancellation.
func (l *SourceListener) Snapshot(ctx context.Context, id string) (SourceExchange, error) {
	if l == nil {
		return SourceExchange{}, ErrPrerequisite
	}
	l.mu.Lock()
	slot := l.slots[id]
	l.mu.Unlock()
	if slot == nil {
		return SourceExchange{}, ErrPrerequisite
	}
	select {
	case <-ctx.Done():
		return SourceExchange{}, ctx.Err()
	case <-slot.ready:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if slot == nil || slot.err != nil || slot.attempts != 1 || slot.exchange.LocalAddress == "" || slot.exchange.RemoteAddress == "" || slot.exchange.PrefixAt.IsZero() {
		return SourceExchange{}, ErrPrerequisite
	}
	x := slot.exchange
	x.RequestBody = append([]byte(nil), x.RequestBody...)
	x.ResponsePrefix = append([]byte(nil), x.ResponsePrefix...)
	return x, nil
}
func (l *SourceListener) Exchange(ctx context.Context, id string) (SourceExchange, error) {
	if l == nil {
		return SourceExchange{}, ErrPrerequisite
	}
	l.mu.Lock()
	slot := l.slots[id]
	l.mu.Unlock()
	if slot == nil {
		return SourceExchange{}, ErrPrerequisite
	}
	select {
	case <-ctx.Done():
		return SourceExchange{}, ctx.Err()
	case <-slot.done:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if slot.err != nil || slot.attempts != 1 || !slot.exchange.CloseSucceeded || slot.exchange.CloseCause == "" || len(slot.exchange.ResponsePrefix) != len(slot.prefix) {
		return SourceExchange{}, ErrPrerequisite
	}
	out := slot.exchange
	out.RequestBody = append([]byte(nil), out.RequestBody...)
	out.ResponsePrefix = append([]byte(nil), out.ResponsePrefix...)
	return out, nil
}

// Serialize the final duplicate check with SAME SQLite completion, preventing a
// reconnect from slipping between the owning receipt check and cap1 release.
func (l *SourceListener) complete(ctx context.Context, id string, e state.OfflineTerminal) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	slot := l.slots[id]
	if slot == nil || slot.err != nil || slot.attempts != 1 || !slot.exchange.CloseSucceeded || slot.exchange.CloseCause == "" {
		return ErrPrerequisite
	}
	select {
	case <-slot.done:
	default:
		return ErrPrerequisite
	}
	raw := sourceSocketOriginal(slot.exchange)
	if model.RawPhysicalDigest(raw) != e.SocketDigest {
		return ErrPrerequisite
	}
	return l.store.CompleteOffline(ctx, e)
}
