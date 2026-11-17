package providergateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	// readBufferBytes is the per-connection read buffer. It is small enough that
	// a request line is assembled in bounded chunks, and larger requests are
	// rejected by readRequestLine.
	readBufferBytes = 32 << 10
	// writeTimeout bounds one response write so a stalled client cannot pin a
	// connection handler forever.
	writeTimeout = 30 * time.Second
)

// errRequestTooLarge is returned by readRequestLine when a line exceeds
// maxRequestBytes. readRequestLine drains the rest of the line before returning
// it, so the connection stays framed and can continue.
var errRequestTooLarge = errors.New("request line exceeds the size limit")

var (
	errGatewayClosed = errors.New("providergateway: gateway is closed")
	errServeCalled   = errors.New("providergateway: Serve may only be called once")
)

// Gateway is one scoped Provider Gateway: one Unix socket, one declared tool
// set, one Executor and one credential lifetime. Create it with New, run it with
// Serve and stop it with Close (or by cancelling the Serve context).
//
// A Gateway is safe for concurrent use by its owner and its connection handlers,
// but Serve may be called at most once and Close is the only supported way to
// stop it early.
type Gateway struct {
	socketPath   string
	rootDir      string
	providerID   string
	connectionID string
	accountID    string
	tools        []Tool
	declared     map[string]struct{}
	executor     Executor
	credential   Credential
	logger       *log.Logger
	toolTimeout  time.Duration

	// credentialKind is the non-secret material kind reported by the optional
	// CredentialDescription extension. It is immutable after New.
	credentialKind string
	// credentialMu serializes credential SecretFields snapshots against the
	// one-time Destroy in teardown. The credential implementations are not
	// required to be internally synchronized.
	credentialMu sync.Mutex

	// secrets holds the credential's secret field values for redaction. It is
	// immutable while serving and zeroized after every handler has stopped.
	secrets [][]byte

	mu           sync.Mutex
	serveStarted bool
	closed       bool
	listener     *net.UnixListener
	listenPath   string
	socketInfo   os.FileInfo
	conns        map[net.Conn]struct{}
	cancelServe  context.CancelFunc

	handlers  sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
}

// New validates the configuration and constructs a Gateway. It performs no I/O:
// the socket directory and socket are prepared by Serve. On success the gateway
// owns the credential and will Destroy it when it closes; on error ownership
// stays with the caller.
func New(config Config) (*Gateway, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	toolTimeout := config.ToolTimeout
	if toolTimeout <= 0 {
		toolTimeout = defaultToolTimeout
	}
	tools := make([]Tool, len(config.Tools))
	declared := make(map[string]struct{}, len(config.Tools))
	for index, tool := range config.Tools {
		tools[index] = Tool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: append(json.RawMessage(nil), tool.InputSchema...),
		}
		declared[tool.Name] = struct{}{}
	}
	var secrets [][]byte
	var credentialKind string
	if config.Credential != nil {
		for _, value := range config.Credential.SecretFields() {
			if value == "" {
				continue
			}
			secrets = append(secrets, []byte(value))
		}
		// Replace longer values first: with a shorter secret that is a substring
		// of a longer one, replacing the short one first could destroy the shape
		// of the longer match without removing all of it.
		sort.Slice(secrets, func(left, right int) bool {
			return len(secrets[left]) > len(secrets[right])
		})
		// The production *boxcredentials.Credential reports its material kind,
		// which the per-call executor snapshot forwards. The extension is
		// optional so narrow test doubles stay valid.
		if description, ok := config.Credential.(CredentialDescription); ok {
			credentialKind = description.CredentialKind()
		}
	}
	return &Gateway{
		socketPath:     config.SocketPath,
		rootDir:        config.RootDir,
		providerID:     config.ProviderID,
		connectionID:   config.ConnectionID,
		accountID:      config.AccountID,
		tools:          tools,
		declared:       declared,
		executor:       config.Executor,
		credential:     config.Credential,
		logger:         logger,
		toolTimeout:    toolTimeout,
		credentialKind: credentialKind,
		secrets:        secrets,
		conns:          make(map[net.Conn]struct{}),
		done:           make(chan struct{}),
	}, nil
}

// Serve prepares the Unix socket and serves MCP requests until ctx is cancelled
// or Close is called. It returns nil on a clean shutdown, including context
// cancellation, and an error when the socket cannot be prepared or accepted.
//
// Serve is single-use: every return path closes the gateway, removes the
// socket when it is still ours, and destroys the credential exactly once.
func (g *Gateway) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errGatewayClosed
	}
	if g.serveStarted {
		g.mu.Unlock()
		return errServeCalled
	}
	g.serveStarted = true
	g.mu.Unlock()

	listener, listenPath, socketInfo, err := prepareSocket(g.socketPath, g.rootDir)
	if err != nil {
		g.logger.Printf("provider gateway: startup failed: %v", err)
		g.teardown()
		return err
	}

	serveCtx, cancelServe := context.WithCancel(ctx)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		cancelServe()
		_ = listener.Close()
		removeSocketFile(listenPath, socketInfo)
		return errGatewayClosed
	}
	g.listener = listener
	g.listenPath = listenPath
	g.socketInfo = socketInfo
	g.cancelServe = cancelServe
	g.mu.Unlock()

	g.logger.Printf(
		"provider gateway: serving providerId=%q connectionId=%q socket=%q tools=%d",
		g.providerID, g.connectionID, listenPath, len(g.tools),
	)

	acceptErrors := make(chan error, 1)
	go g.acceptLoop(serveCtx, listener, acceptErrors)

	var acceptErr error
	select {
	case <-serveCtx.Done():
		// Context cancelled or Close started the teardown.
	case <-g.done:
		// Close() was called.
	case acceptErr = <-acceptErrors:
	}

	g.teardown()
	g.logger.Printf("provider gateway: closed socket=%q", listenPath)
	if acceptErr != nil {
		return fmt.Errorf("providergateway: accept: %w", acceptErr)
	}
	return nil
}

// Close stops the gateway: it closes the listener, closes every active
// connection, removes the socket file when it is still this gateway's socket,
// and destroys the credential. It is idempotent, and it is valid to call Close
// without (or before) Serve.
//
// Close does not wait for connection handlers that are inside an Executor call;
// those calls are bounded by Config.ToolTimeout and are cancelled through the
// Serve context.
func (g *Gateway) Close() error {
	g.teardown()
	return nil
}

// acceptLoop accepts connections until the listener is closed. A genuine accept
// error is reported once to Serve; errors caused by teardown are silent.
func (g *Gateway) acceptLoop(ctx context.Context, listener *net.UnixListener, errorsOut chan<- error) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if g.isClosed() {
				return
			}
			select {
			case errorsOut <- err:
			default:
			}
			return
		}
		if !g.trackConn(conn) {
			_ = conn.Close()
			return
		}
		go func() {
			defer g.untrackConn(conn)
			g.serveConn(ctx, conn)
		}()
	}
}

// serveConn serves one newline-delimited JSON-RPC connection sequentially. MCP
// over stdio is a single logical session, so requests on one connection are
// ordered; concurrency comes from independent connections.
func (g *Gateway) serveConn(ctx context.Context, conn net.Conn) {
	reader := bufio.NewReaderSize(conn, readBufferBytes)
	for {
		line, err := readRequestLine(reader)
		if err != nil {
			if errors.Is(err, errRequestTooLarge) {
				if writeErr := writeResponseLine(conn, encodeErrorResponse(nil, newRPCError(codeInvalidRequest, "request too large"))); writeErr != nil {
					return
				}
				continue
			}
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			// Tolerate blank keepalive lines between requests.
			continue
		}
		response := g.dispatch(ctx, line)
		if response == nil {
			continue
		}
		if err := writeResponseLine(conn, response); err != nil {
			return
		}
	}
}

// writeResponseLine writes one response line with a bounded write deadline. A
// response is a single Write so a client cannot interleave two responses.
func writeResponseLine(conn net.Conn, line []byte) error {
	payload := make([]byte, 0, len(line)+1)
	payload = append(payload, line...)
	payload = append(payload, '\n')
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// readRequestLine reads one newline-terminated request line, bounded by
// maxRequestBytes. A trailing CR (CRLF framing) is tolerated. A partial line at
// EOF is dropped: the newline is the frame delimiter.
//
// An oversized line is fully drained before errRequestTooLarge is returned, so
// the connection stays framed and can serve the next request; without the drain
// the client would wait for a response while the server waited for a newline.
func readRequestLine(reader *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, 512)
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > maxRequestBytes {
			switch {
			case err == nil:
				// The fragment already contained the newline; the line is drained.
				return nil, errRequestTooLarge
			case errors.Is(err, bufio.ErrBufferFull):
				if drainErr := drainRequestLine(reader); drainErr != nil {
					return nil, drainErr
				}
				return nil, errRequestTooLarge
			default:
				return nil, err
			}
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			line = bytes.TrimSuffix(line, []byte{'\n'})
			line = bytes.TrimSuffix(line, []byte{'\r'})
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

// drainRequestLine discards the remainder of an oversized line so the
// connection stays framed and can receive further requests.
func drainRequestLine(reader *bufio.Reader) error {
	for {
		_, err := reader.ReadSlice('\n')
		switch {
		case err == nil:
			return nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return io.ErrUnexpectedEOF
		default:
			return err
		}
	}
}

// trackConn registers an accepted connection and its handler. It returns false
// once teardown has started, so no handler is added after the handler wait
// group begins waiting on shutdown.
func (g *Gateway) trackConn(conn net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.conns[conn] = struct{}{}
	g.handlers.Add(1)
	return true
}

// untrackConn closes a connection and marks its handler finished. Done is
// called only after the handler no longer uses the redaction secrets.
func (g *Gateway) untrackConn(conn net.Conn) {
	g.mu.Lock()
	delete(g.conns, conn)
	g.mu.Unlock()
	_ = conn.Close()
	g.handlers.Done()
}

func (g *Gateway) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// teardown performs the one-time shutdown: stop accepting, cancel in-flight
// calls, close live connections, remove our socket, destroy the credential and
// unblock Serve. It is safe to call from Close, from Serve, or both.
func (g *Gateway) teardown() {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closed = true
		listener := g.listener
		cancelServe := g.cancelServe
		listenPath := g.listenPath
		socketInfo := g.socketInfo
		conns := make([]net.Conn, 0, len(g.conns))
		for conn := range g.conns {
			conns = append(conns, conn)
		}
		g.mu.Unlock()

		if cancelServe != nil {
			cancelServe()
		}
		if listener != nil {
			_ = listener.Close()
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
		removeSocketFile(listenPath, socketInfo)
		if g.credential != nil {
			// Serialize the one-time Destroy against per-call SecretFields
			// snapshots: a handler that is still inside an Executor call when
			// teardown starts must never observe a partially destroyed
			// credential.
			g.credentialMu.Lock()
			g.credential.Destroy()
			g.credentialMu.Unlock()
		}

		// Zero the redaction copies only after every connection handler has
		// stopped, so a live handler can never observe a partially redacted
		// secret list.
		go func() {
			g.handlers.Wait()
			g.releaseSecrets()
		}()

		close(g.done)
	})
}

// releaseSecrets zeroizes and drops the transient redaction copies of the
// credential secret values. It runs once, after all handlers stopped.
func (g *Gateway) releaseSecrets() {
	for index := range g.secrets {
		for offset := range g.secrets[index] {
			g.secrets[index][offset] = 0
		}
	}
	g.secrets = nil
}
