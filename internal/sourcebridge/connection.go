// Package sourcebridge authenticates already-connected host SOURCE sockets. It
// creates no listener, physical authority, native identity or process. The owning
// harness pins the peer outside the request; the daemon never enables this path.
package sourcebridge

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type Peer struct {
	PID      int
	UID, GID uint32
}

func ServeConnected(ctx context.Context, conn *net.UnixConn, expected Peer, dispatch func(context.Context, io.Reader, io.Writer) error) error {
	if conn == nil {
		return errors.New("SOURCE connected owner absent")
	}
	defer conn.Close()
	if dispatch == nil || expected.PID < 1 || ctx.Err() != nil {
		return errors.New("SOURCE peer pin/dispatcher absent")
	}
	deadline := time.Now().Add(30 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	actual, err := socketPeer(conn)
	if err != nil || actual != expected {
		return errors.New("SOURCE kernel peer does not match owning harness pin")
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(call, func() { _ = conn.Close() })
	defer stop()
	return dispatch(call, conn, conn)
}
