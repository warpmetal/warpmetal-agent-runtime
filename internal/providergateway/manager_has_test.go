package providergateway

import (
	"context"
	"testing"
)

func TestManagerHasTracksRunningGatewayBySandboxAndRun(t *testing.T) {
	fixture := newManagerFixture(t)
	if fixture.manager.Has(managerSandboxID, managerRunID) {
		t.Fatal("manager reported an unstarted gateway as running")
	}
	if fixture.manager.Has("", managerRunID) ||
		fixture.manager.Has(managerSandboxID, "") ||
		fixture.manager.Has("", "") {
		t.Fatal("manager reported a gateway for empty identifiers")
	}

	started := fixture.start(fixture.request(managerRunID))
	if !fixture.manager.Has(managerSandboxID, managerRunID) {
		t.Fatal("manager did not report the running gateway")
	}
	otherRun := fixture.start(fixture.request("run_manager0002"))
	if !fixture.manager.Has(managerSandboxID, "run_manager0002") {
		t.Fatal("manager did not report the second running gateway")
	}
	if fixture.manager.Has(managerSandboxID, "run_unknown0001") ||
		fixture.manager.Has("sbx_unknown0001", managerRunID) {
		t.Fatal("manager matched a gateway by an unknown exact pair")
	}

	if err := started.handle.Close(context.Background()); err != nil {
		t.Fatalf("close gateway: %v", err)
	}
	waitHandleDone(t, started.handle)
	if fixture.manager.Has(managerSandboxID, managerRunID) {
		t.Fatal("manager still reports a closed gateway")
	}
	if !fixture.manager.Has(managerSandboxID, "run_manager0002") {
		t.Fatal("closing one gateway detached an unrelated one")
	}

	if err := fixture.manager.CloseSandbox(context.Background(), managerSandboxID); err != nil {
		t.Fatalf("close sandbox gateways: %v", err)
	}
	waitHandleDone(t, otherRun.handle)
	if fixture.manager.Has(managerSandboxID, "run_manager0002") {
		t.Fatal("manager still reports a gateway closed by CloseSandbox")
	}
}

func TestManagerHasIgnoresRefusedStarts(t *testing.T) {
	fixture := newManagerFixture(t)
	request := fixture.request(managerRunID)
	request.RunID = "run/unsafe"
	request.Credential = newFakeCredential(fakeSecret)
	if handle, err := fixture.manager.Start(context.Background(), request); err == nil || handle != nil {
		t.Fatalf("manager accepted an unsafe run id: %#v %v", handle, err)
	}
	if fixture.manager.Has(managerSandboxID, request.RunID) {
		t.Fatal("refused start left the gateway visible to Has")
	}
}
