package access

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"sync"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
)

// foreman chat frame tracing is an explicitly enabled, TEST-venue forensic
// switch. It is off by default and adds no product behavior; it exists to make
// the exact owner<->bridge frame path observable when a handshake stalls.
var foremanChatTraceEnabled = os.Getenv("WARPMETAL_FOREMAN_CHAT_TRACE") == "1"

func foremanChatTracef(format string, args ...any) {
	if !foremanChatTraceEnabled {
		return
	}
	log.Printf("foreman chat trace: "+format, args...)
}

func frameHead(payload []byte, limit int) string {
	if len(payload) < limit {
		limit = len(payload)
	}
	return hex.EncodeToString(payload[:limit])
}

func frameDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:8])
}

// frameTraceWriter records the exact byte stream the Runtime writes toward the
// owner for one handoff (bridge ACK, response frames, exit trailer).
type frameTraceWriter struct {
	writer io.Writer
	mu     sync.Mutex
	writes int
	bytes  int
}

func (w *frameTraceWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	index := w.writes
	w.writes++
	w.bytes += len(payload)
	w.mu.Unlock()
	if index < 96 {
		foremanChatTracef("owner<-runtime bytes=%d total=%d head=%s", len(payload), w.bytes, frameHead(payload, 8))
	}
	return w.writer.Write(payload)
}

// inputTraceReader records the exact bytes the owner sends toward the bridge
// after the handoff preface (the HELLO frame itself is replayed by
// ExecSessionHandoff, so this stream starts with the first request frame).
type inputTraceReader struct {
	input containers.SessionInput
	mu    sync.Mutex
	reads int
	bytes int
}

func (r *inputTraceReader) Read(payload []byte) (int, error) {
	n, err := r.input.Read(payload)
	if n > 0 {
		r.mu.Lock()
		index := r.reads
		r.reads++
		r.bytes += n
		r.mu.Unlock()
		if index < 96 {
			foremanChatTracef("owner->runtime bytes=%d total=%d head=%s", n, r.bytes, frameHead(payload[:n], 8))
		}
	}
	return n, err
}

func (r *inputTraceReader) InterruptRead() error { return r.input.InterruptRead() }
