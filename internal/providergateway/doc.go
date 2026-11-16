// Package providergateway implements the scoped Provider Gateway for the
// Runtime Box credential bridge (Phase P2).
//
// The gateway is a local-only MCP server that exposes exactly the tool-provider
// tools a workspace template declared. The sandbox agent reaches it through
// socat, the same way a stdio MCP server is reached:
//
//	socat - UNIX-CONNECT:/run/warpmetal/provider/gateway.sock
//
// Wire protocol. The gateway speaks newline-delimited JSON-RPC 2.0 and a small,
// deliberately closed subset of MCP:
//
//   - initialize: negotiates a supported protocol version (a supported
//     requested version is echoed, anything else gets DefaultProtocolVersion),
//     advertises only the tools capability, and reports ServerName.
//   - notifications/initialized: accepted and never answered.
//   - tools/list: exactly the declared tools, with their input schemas.
//   - tools/call: only declared tool names reach the Executor; anything else is
//     a JSON-RPC invalid-params error. Tool-level failures come back as MCP
//     content with isError=true so the model can see them without the client
//     treating the whole session as broken.
//   - ping: an empty result.
//   - everything else: JSON-RPC method-not-found (-32601).
//
// The gateway is intentionally not a general MCP server: it has no resources,
// prompts, sampling, logging or server-initiated messages, and it advertises no
// capability besides tools. JSON-RPC batches are not accepted. Requests and
// responses are bounded, and every executor call has a deadline.
//
// Security invariants:
//
//   - The opened provider credential is held only in memory. An Executor never
//     receives it: CallTool sees only the tool name and arguments, so a
//     provider implementation cannot accidentally return credential material.
//     The gateway keeps a transient copy of the credential's secret field
//     values solely to redact them from executor error text and tool result
//     text, and zeroizes that copy once the gateway has stopped. Credential
//     material is never logged, and Config is never serialized.
//   - The Unix socket is created 0600 inside a directory the gateway creates
//     0700; an existing directory must already be owner-only. The socket file
//     is removed on close only while it is still the exact socket this gateway
//     created.
//   - Error text surfaced to clients and logs is length-bounded, sanitized and
//     redacted before it leaves the process.
//
// Lifecycle. New validates configuration and performs no I/O. Serve prepares
// the socket, serves until the context is cancelled or Close is called, then
// tears everything down; on return the gateway is permanently closed and its
// credential has been destroyed. Serve may be called at most once. The gateway
// owns exactly one credential and exactly one socket.
//
// Phase scope. There are no real provider calls yet and nothing wires this
// package into the sandbox, the Runtime serve loop or a control plane:
// Executor implementations are supplied by the caller (tests use a fake
// provider that exposes fake_read and fake_write). An Executor must be safe for
// concurrent use because connections are served concurrently.
package providergateway
