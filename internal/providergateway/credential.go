package providergateway

// This file owns the per-call credential snapshot the gateway hands an
// Executor. Phase P4a delegates real provider execution to a reviewed external
// command that is the provider execution boundary, so that executor must
// receive the credential material for the call. The snapshot is deliberately
// short-lived: it is built immediately before one CallTool invocation and
// scrubbed immediately after it, and the gateway remains the only owner of the
// opened credential (it destroys it exactly once on teardown).

// toolCallCredential builds the per-call credential snapshot from the opened
// credential. It returns nil when the gateway holds no credential, or when the
// credential has no secret field values. The credential lock serializes the
// snapshot against Destroy, so a handler that races gateway teardown can never
// observe a partially destroyed credential.
func (g *Gateway) toolCallCredential() *ToolCredential {
	if g.credential == nil {
		return nil
	}
	g.credentialMu.Lock()
	fields := g.credential.SecretFields()
	g.credentialMu.Unlock()
	if len(fields) == 0 {
		return nil
	}
	return &ToolCredential{Kind: g.credentialKind, Fields: fields}
}

// releaseToolCredential scrubs and drops one per-call snapshot after the
// Executor returned. Go strings are immutable, so this is best-effort: it
// removes the map entries and lengths the window in which the executor's value
// copies exist, and it guarantees the gateway retains no reference afterwards.
func releaseToolCredential(credential *ToolCredential) {
	if credential == nil {
		return
	}
	for name := range credential.Fields {
		credential.Fields[name] = ""
		delete(credential.Fields, name)
	}
	credential.Fields = nil
	credential.Kind = ""
}

// executorToolCall assembles the ToolCall for one declared tools/call request,
// attaching the gateway's non-secret binding metadata and the per-call
// credential snapshot. The caller must call releaseToolCredential on the result
// after the Executor returned.
func (g *Gateway) executorToolCall(name string, arguments []byte) ToolCall {
	call := ToolCall{
		Name:         name,
		Arguments:    arguments,
		ProviderID:   g.providerID,
		ConnectionID: g.connectionID,
		AccountID:    g.accountID,
		Credential:   g.toolCallCredential(),
	}
	return call
}
