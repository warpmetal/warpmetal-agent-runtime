package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	control "github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/boxcredentials"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/capacity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/config"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/continuity"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/insights"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/manager"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/reconcile"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/storage"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

var version = "dev"

const (
	controlPlaneTimeout = 45 * time.Second
	reconcileTimeout    = 10*time.Minute + 5*time.Second
)

func main() {
	// The release stamp is normally injected with `-X main.version=...` (see the
	// Makefile/release workflow). Operators and the installer need an
	// unauthenticated, side-effect-free way to prove which artifact is
	// installed, so `--version`/`version` never loads config or state.
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "version", "--version", "-version":
			fmt.Printf("warpmetald %s\n", version)
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "register" {
		if err := register(os.Args[2:]); err != nil {
			log.Fatal(bounded(err.Error()))
		}
		return
	}
	arguments := os.Args[1:]
	// `warpmetald serve [flags]` is the documented operator form. Accept the
	// explicit subcommand by removing it before flag parsing; Go's flag package
	// stops at the first non-flag argument, which previously made every serve
	// flag after `serve` silently ignored (D-WP20-1).
	if len(arguments) > 0 && arguments[0] == "serve" {
		arguments = arguments[1:]
	}
	if err := serve(arguments); err != nil {
		// `-h`/`--help` already printed the versioned usage; it is not a
		// daemon failure.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Fatal(bounded(err.Error()))
	}
}

func register(arguments []string) error {
	return registerWithInputs(arguments, os.Stdin, readHostKeys, nil)
}

// Registration orchestration keeps process inputs at the command boundary. The
// public key reader and HTTP client retain their normal defaults in register.
func registerWithInputs(arguments []string, stdin io.Reader, publicHostKeys func() ([]model.HostKey, error), httpClient *http.Client) error {
	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	apiOrigin := flags.String("api", "https://api.warpmetal.com", "WarpMetal API origin")
	serverID := flags.String("server", "", "registered server ID")
	configPath := flags.String("config", "/var/lib/warpmetal/runtime.json", "root-only config path")
	imageDigest := flags.String("image-digest", "", "optional exact candidate Sandbox sha256 digest")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !strings.HasPrefix(*serverID, "srv_") {
		return errors.New("a valid --server is required")
	}
	if *imageDigest != "" && !model.PhysicalDigestValid(*imageDigest) {
		return errors.New("a valid --image-digest is required")
	}
	// Registration rotates the node credential. Refuse an existing config before
	// consuming the bootstrap; an old producer pin cannot authorize that rotation.
	// This check does not reserve an absent path against concurrent registration.
	if _, err := os.Lstat(*configPath); err == nil {
		return errors.New("runtime_registration_config_exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("runtime_registration_config_unavailable: %w", err)
	}
	reader := bufio.NewReader(io.LimitReader(stdin, 513))
	bootstrap, err := reader.ReadString('\n')
	if err != nil && bootstrap == "" {
		return errors.New("bootstrap token is required on stdin")
	}
	bootstrap = strings.TrimSpace(bootstrap)
	if len(bootstrap) > 512 {
		return errors.New("bootstrap input is too large")
	}
	if !strings.HasPrefix(bootstrap, "rtb_") {
		return errors.New("bootstrap token is invalid")
	}
	hostKeys, err := publicHostKeys()
	if err != nil {
		return err
	}
	client := control.Client{Origin: *apiOrigin, HTTP: httpClient}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	registered, err := client.Register(ctx, bootstrap, control.Registration{
		ServerID:          *serverID,
		SupervisorVersion: version,
		ImageDigest:       *imageDigest,
		HostKeys:          hostKeys,
	})
	bootstrap = ""
	if err != nil {
		return err
	}
	return config.Save(*configPath, config.Config{
		APIOrigin:          *apiOrigin,
		ServerID:           registered.ServerID,
		NodeToken:          registered.NodeToken,
		NodeTokenExpiresAt: registered.ExpiresAt,
	})
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("warpmetald", flag.ContinueOnError)
	// Help output identifies the exact stamped artifact, so an installed host
	// can be checked with `warpmetald --help` as well as `--version`.
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "warpmetald %s\n", version)
		flags.PrintDefaults()
	}
	stateRoot := flags.String("state-dir", "/var/lib/warpmetal", "runtime state directory")
	workspaceRoot := flags.String(
		"workspace-dir",
		"/var/lib/warpmetal-workspaces",
		"sandbox workspace image directory",
	)
	configPath := flags.String("config", "/var/lib/warpmetal/runtime.json", "root-only config path")
	socketPath := flags.String("socket", "/run/warpmetal/supervisor.sock", "gateway socket")
	accessPath := flags.String(
		"authorized-keys",
		"/etc/ssh/warpmetal-runtime/authorized_keys",
		"generated gateway key map",
	)
	poll := flags.Duration("poll", 10*time.Second, "control-plane poll interval")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	settings, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load registration: %w", err)
	}
	store, err := state.Open(filepath.Join(*stateRoot, "runtime.sqlite3"))
	if err != nil {
		return err
	}
	defer store.Close()
	hostCapacity, err := capacity.Detect(*workspaceRoot)
	if err != nil {
		return fmt.Errorf("detect host capacity: %w", err)
	}
	hostKeys, err := readHostKeys()
	if err != nil {
		return err
	}
	engine := containers.Podman{RuntimeUser: "warpmetal-runtime", QualificationRoot: settings.QualificationRoot,
		QualificationProducer: settings.QualificationProducer, QualificationServerID: settings.ServerID,
		QualificationNodeTokenHash: fmt.Sprintf("%x", sha256.Sum256([]byte(settings.NodeToken))),
		// A Runtime instance is bound to exactly one backend task by its node
		// token, so this operator-only configuration is scoped to that test
		// instance. It is absent for production installs.
		SetupTestSource: settings.SetupTestSource}
	var physicalListener net.Listener
	var physicalErrors chan error
	var processes *physicalgate.ProcessRegistry
	if settings.QualificationRoot != "" {
		listener, err := physicalgate.ListenProtected()
		if err != nil {
			return fmt.Errorf("physical gate endpoint: %w", err)
		}
		physicalListener = listener
		defer physicalListener.Close()
		engine.PhysicalStore = store
		engine.PhysicalAccess = &physicalgate.AccessRegistry{Store: store}
		processes = &physicalgate.ProcessRegistry{Store: store}
		engine.PhysicalProcesses = processes
		processes.ObserveContainer = engine.ObservePhysicalContainer
		// SOURCE fixture listener ownership remains private and dormant without
		// an independently admitted window + genuine protected fixture/certificate.
		// Missing current signed control/terminal reader denies completion; never
		// fill that boundary with a grant's reflected reference or a new issuer.
		sourceListener := physicalgate.NewSourceListener(store)
		engine.SourceTerminal = &physicalgate.SourceTerminalConsumer{Store: store, Listener: sourceListener, Reader: physicalgate.RegisteredSourceTerminalReader{Processes: processes, NativeReader: engine}}
		physicalErrors = make(chan error, 1)
		// The listener is owned before any container create. Its handler is wired
		// below to the SAME reconciler's current signed authority, never test facts.
	}
	client := control.Client{Origin: settings.APIOrigin, NodeToken: settings.NodeToken, HTTP: controlPlaneHTTPClient()}
	gateway, err := newAccessGateway(store, containers.Podman{RuntimeUser: "warpmetal-runtime"}, hostKeys, client)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The sealed tool-provider credential bridge is opt-in (Phase P1). With the
	// field absent or disabled this starts nothing: no key is generated and no
	// credential HTTP call is made, so production behavior is unchanged.
	credentialBridge, stopCredentialBridge, err := startToolCredentialBridge(ctx, settings, client, *stateRoot)
	if err != nil {
		return err
	}
	defer stopCredentialBridge()
	reconciler := newRuntimeReconciler(store, engine, *workspaceRoot, *accessPath, gateway, hostCapacity, settings.ServerID, *stateRoot, client, ctx)
	// Phase P2d: wire the scoped provider gateway lifecycle only when the opt-in
	// credential bridge is enabled (the credential opener). The executor stays
	// nil: no production provider execution is enabled, so a manifest that
	// declares providerGateways fails the pass closed instead of making real
	// provider calls. With the bridge disabled nothing is constructed.
	stopProviderGateways := configureProviderGateways(reconciler, credentialBridge, nil)
	defer stopProviderGateways()
	if physicalListener != nil {
		gate := physicalgate.Server{Store: store, Authority: physicalgate.RuntimeAuthority{Processes: processes, Access: engine.PhysicalAccess, Resolve: reconciler.AuthorizePhysicalRequest, CommitProviderSettlement: reconciler.CommitProviderPhysicalSettlement}}
		go func() { physicalErrors <- gate.Serve(physicalListener) }()
	}
	reportSync := &reconcile.ReportSync{
		Post: func(ctx context.Context, report model.Report) (reconcile.ReportAck, error) {
			ack, err := client.ReportAck(ctx, report)
			return reconcile.ReportAck{
				ReportEpoch: ack.ReportEpoch, DesiredRevision: ack.DesiredRevision,
				AppliedRevision:  ack.AppliedRevision,
				ResyncGeneration: ack.ResyncGeneration, Replayed: ack.Replayed,
			}, err
		},
		Manifest: func(ctx context.Context) (model.Manifest, error) {
			return client.Manifest(ctx)
		},
		Store: store,
	}
	loop := runtimeFeedbackLoop{
		reconciler:          reconciler,
		client:              client,
		reportSync:          reportSync,
		serverID:            settings.ServerID,
		version:             version,
		hostKeys:            hostKeys,
		controlPlaneTimeout: controlPlaneTimeout,
		reconcileTimeout:    reconcileTimeout,
	}
	// A setup owner redrive supersedes the failed operation and creates a new
	// immutable setup generation; a report body built before that change still
	// carries the superseded tuple and can never be accepted. Rebuild re-runs the
	// same bounded reconcile against the freshly read manifest (adopting the new
	// setup generation) and returns the current report body.
	reportSync.Rebuild = func(reportCtx context.Context, manifest model.Manifest) (*model.Report, error) {
		reconcileContext, cancelReconcile := context.WithTimeout(reportCtx, reconcileTimeout)
		err := reconciler.Reconcile(reconcileContext, manifest)
		cancelReconcile()
		if err != nil {
			return nil, err
		}
		rebuilt, err := reconciler.Report(reportCtx, settings.ServerID, version)
		if err != nil {
			return nil, err
		}
		rebuilt.HostKeys = hostKeys
		if manifest.ImageDigest != "" {
			rebuilt.ImageDigest = manifest.ImageDigest
		}
		return &rebuilt, nil
	}
	gatewayErrors := make(chan error, 1)
	go func() { gatewayErrors <- gateway.Serve(ctx, *socketPath) }()
	ticker := time.NewTicker(maxDuration(*poll, 2*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-gatewayErrors:
			if err != nil {
				return fmt.Errorf("gateway stopped: %w", err)
			}
		case err := <-physicalErrors:
			if ctx.Err() == nil {
				return fmt.Errorf("physical gate stopped: %w", err)
			}
		case <-ticker.C:
			loop.pass(ctx)
		}
	}
}

// controlPlaneHTTPClient is the shared control-plane transport. Its per-request
// timeout equals the control-plane budget (45s) instead of the api.Client's
// 30s fallback: every call the loop makes is already bounded by its own
// context, and a transport that aborts BEFORE that budget turns a
// healthy-but-loaded venue into a client-side timeout. Measured in the WP-121
// epoch: the credential fetch needed 31.4-37.1s and the report endpoint
// exceeded 30s at 03:39:21 (R-WP120-1). Nothing is weakened for other
// endpoints: the loop still bounds manifest/report/application calls with
// controlPlaneTimeout, and the reconciler's pass context still bounds the rest.
func controlPlaneHTTPClient() *http.Client {
	return &http.Client{Timeout: controlPlaneTimeout}
}

// startToolCredentialBridge starts the opt-in Runtime Box credential bridge
// (Phase P1). Disabled configuration is inert by construction: it returns a nil
// manager and a no-op stop without touching the state directory or calling the
// platform. When enabled, the returned manager is the Runtime's credential
// opener for Phase P2d, and shutdown cancels the bridge context and waits a
// bounded time for its Run loop to finish.
func startToolCredentialBridge(ctx context.Context, settings config.Config, client control.Client, stateRoot string) (*boxcredentials.Manager, func(), error) {
	if !settings.ToolCredentialBridgeEnabled() {
		return nil, func() {}, nil
	}
	bridge, err := boxcredentials.New(boxcredentials.Options{
		Enabled:      true,
		StateDir:     stateRoot,
		Client:       client,
		BoxID:        settings.ServerID,
		PollInterval: settings.ToolCredentialBridge.PollInterval(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tool credential bridge: %w", err)
	}
	bridgeContext, cancel := context.WithCancel(ctx)
	go func() {
		if err := bridge.Run(bridgeContext); err != nil {
			log.Printf("tool credential bridge stopped: %s", bounded(err.Error()))
		}
	}()
	return bridge, func() {
		cancel()
		select {
		case <-bridge.Done():
		case <-time.After(5 * time.Second):
			log.Printf("tool credential bridge did not stop within the shutdown budget")
		}
	}, nil
}

// configureProviderGateways wires the Phase P2d scoped provider gateway
// lifecycle into the reconciler. It constructs a provider gateway manager only
// when the opt-in Box credential bridge is enabled, because that manager is the
// only configured credential opener; with the bridge disabled (nil manager) it
// constructs nothing and returns a no-op shutdown. The returned function closes
// every gateway and is safe to call once at daemon shutdown.
//
// The executor is supplied by the caller. Phase P2d passes nil: production
// provider execution is not enabled, so a manifest that declares provider
// gateways fails the reconcile pass closed with an explicit feature-not-enabled
// error instead of making real provider calls.
func configureProviderGateways(
	runtimeReconciler *reconcile.Reconciler,
	credentialBridge *boxcredentials.Manager,
	executor providergateway.Executor,
) func() {
	if credentialBridge == nil || runtimeReconciler == nil {
		return func() {}
	}
	gatewayManager := providergateway.NewManager(nil)
	runtimeReconciler.ProviderGateways = reconcile.ProviderGateways{Manager: gatewayManager}
	runtimeReconciler.ProviderCredentials = reconcile.BoxCredentialOpener{Manager: credentialBridge}
	runtimeReconciler.ProviderExecutor = executor
	return func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := gatewayManager.Close(shutdown); err != nil {
			log.Printf("provider gateway manager shutdown: %s", bounded(err.Error()))
		}
	}
}

// runtimeFeedbackLoop performs one serial control-loop pass. It is the
// extracted, directly callable unit of the daemon tick; the heavy lifecycle
// order is unchanged and the post-ACK automatic feedback phase is bounded.
type runtimeFeedbackLoop struct {
	reconciler          *reconcile.Reconciler
	client              control.Client
	serverID            string
	version             string
	hostKeys            []model.HostKey
	reportSync          *reconcile.ReportSync
	controlPlaneTimeout time.Duration
	reconcileTimeout    time.Duration
	// feedbackWait is an optional context-aware wait hook. Production defaults
	// to a bounded timer; tests may observe or interrupt the wait.
	feedbackWait func(context.Context, time.Duration) bool
	// feedbackWindowOverride/feedbackCadenceOverride exist only so bounded
	// tests can scale the fixed feedback budget. Production always uses the
	// constants below.
	feedbackWindowOverride  time.Duration
	feedbackCadenceOverride time.Duration
}

const (
	feedbackWindow  = 120 * time.Second
	feedbackCadence = 10 * time.Second
)

// window is the whole post-ACK feedback budget: 120s in production.
func (l *runtimeFeedbackLoop) window() time.Duration {
	if l.feedbackWindowOverride > 0 {
		return l.feedbackWindowOverride
	}
	return feedbackWindow
}

// cadence is the bounded tail poll interval: 10s in production.
func (l *runtimeFeedbackLoop) cadence() time.Duration {
	if l.feedbackCadenceOverride > 0 {
		return l.feedbackCadenceOverride
	}
	return feedbackCadence
}

// actionCeiling bounds one feedback action by the parent phase deadline and the
// normal reconcile ceiling. It never floors an expired parent back to life.
func (l *runtimeFeedbackLoop) actionCeiling(ctx context.Context) time.Duration {
	remaining := l.reconcileTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < remaining {
			remaining = left
		}
	}
	return remaining
}

// waitFor waits one bounded interval, clamped to the parent phase deadline and
// interrupted by its cancellation. It reports whether the wait completed.
func (l *runtimeFeedbackLoop) waitFor(ctx context.Context, cadence time.Duration) bool {
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < cadence {
			cadence = remaining
		}
	}
	if cadence <= 0 {
		return false
	}
	if l.feedbackWait != nil {
		return l.feedbackWait(ctx, cadence)
	}
	timer := time.NewTimer(cadence)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// pass runs one heavy lifecycle pass, publishes its real Report and requires a
// successful Backend ACK before the post-ACK automatic feedback phase. The
// final Report sends the resulting metadata outside the feedback window.
func (l *runtimeFeedbackLoop) pass(ctx context.Context) {
	expireContext, cancelExpire := context.WithTimeout(ctx, l.controlPlaneTimeout)
	err := l.reconciler.Expire(expireContext)
	cancelExpire()
	var manifest model.Manifest
	if err == nil {
		manifestContext, cancelManifest := context.WithTimeout(ctx, l.controlPlaneTimeout)
		manifest, err = l.client.Manifest(manifestContext)
		cancelManifest()
	}
	if err == nil {
		reconcileContext, cancelReconcile := context.WithTimeout(ctx, l.reconcileTimeout)
		err = l.reconciler.Reconcile(reconcileContext, manifest)
		cancelReconcile()
	}
	reportContext, cancelReport := context.WithTimeout(ctx, l.controlPlaneTimeout)
	report, reportErr := l.reconciler.Report(reportContext, l.serverID, l.version)
	report.HostKeys = l.hostKeys
	if manifest.ImageDigest != "" {
		report.ImageDigest = manifest.ImageDigest
	}
	if err != nil {
		report.LastError = &model.ItemError{
			Code:    "reconcile_failed",
			Message: bounded(err.Error()),
		}
	}
	if reportErr == nil {
		if l.reportSync != nil {
			reportErr = l.reportSync.Send(reportContext, &report)
		} else {
			reportErr = l.client.Report(reportContext, report)
		}
	}
	cancelReport()
	if reportErr != nil {
		log.Printf("runtime report failed: %s", bounded(reportErr.Error()))
	}
	if err != nil || reportErr != nil {
		return
	}
	applicationContext, cancelApplication := context.WithTimeout(ctx, l.controlPlaneTimeout)
	applicationErr := l.reconciler.CompleteWorkspaceApplications(applicationContext, report)
	cancelApplication()
	if applicationErr != nil {
		// P7j acceptance redrive: retry from durable ACKed parent reports when the
		// post-report acceptance response was lost or raced with a parent insert.
		redriveContext, cancelRedrive := context.WithTimeout(ctx, l.controlPlaneTimeout)
		redriveErr := l.reconciler.RedriveWorkspaceApplications(redriveContext)
		cancelRedrive()
		if redriveErr != nil {
			log.Printf("workspace application receipt failed: %s (redrive: %s)",
				bounded(applicationErr.Error()), bounded(redriveErr.Error()))
			return
		}
		log.Printf("workspace application acceptance redriven after: %s", bounded(applicationErr.Error()))
	}
	l.feedback(ctx)
	finalContext, cancelFinal := context.WithTimeout(ctx, l.controlPlaneTimeout)
	finalReport, finalErr := l.reconciler.Report(finalContext, l.serverID, l.version)
	finalReport.HostKeys = l.hostKeys
	if manifest.ImageDigest != "" {
		finalReport.ImageDigest = manifest.ImageDigest
	}
	if finalErr == nil {
		if l.reportSync != nil {
			finalErr = l.reportSync.Send(finalContext, &finalReport)
		} else {
			finalErr = l.client.Report(finalContext, finalReport)
		}
	}
	cancelFinal()
	if finalErr != nil {
		log.Printf("runtime report failed: %s", bounded(finalErr.Error()))
	}
}

// feedback runs the post-ACK automatic feedback phase under ONE parent
// deadline created before the first fresh fetch. The fresh validated manifest,
// collector, automatic admission and the bounded serial progression loop all
// inherit that parent while retaining their ordinary per-request timeouts;
// per-run actions are additionally capped by the durable original run lease in
// the Coordinator. A start failure keeps its durable unknown phase and the
// rounds continue observation-only; cancellation or expiry stops the phase and
// the final Report runs on the outer context.
func (l *runtimeFeedbackLoop) feedback(ctx context.Context) {
	manager, ok := l.reconciler.AutomaticFeedback()
	if !ok {
		return
	}
	parent, cancelParent := context.WithTimeout(ctx, l.window())
	defer cancelParent()
	fetch := func() bool {
		freshContext, cancelFresh := context.WithTimeout(parent, l.controlPlaneTimeout)
		fresh, err := l.client.Manifest(freshContext)
		cancelFresh()
		if err != nil {
			return false
		}
		applyContext, cancelApply := context.WithTimeout(parent, l.controlPlaneTimeout)
		defer cancelApply()
		return l.reconciler.ApplyFeedbackManifest(applyContext, fresh) == nil
	}
	if !fetch() {
		return
	}
	if l.reconciler.Insights != nil {
		insightContext, cancelInsights := context.WithTimeout(parent, l.controlPlaneTimeout)
		err := l.reconciler.Insights.RunOnce(insightContext)
		cancelInsights()
		if err != nil {
			log.Printf("runtime insights failed: %s", bounded(err.Error()))
			return
		}
	}
	admissionContext, cancelAdmission := context.WithTimeout(parent, l.actionCeiling(parent))
	err := manager.ReconsiderAdmissions(admissionContext)
	cancelAdmission()
	if err != nil {
		// The durable execution_unknown phase is retained; the bounded rounds
		// continue observation-only instead of ending the whole phase.
		log.Printf("runtime automatic admission failed: %s", bounded(err.Error()))
	}
	for parent.Err() == nil {
		if !fetch() {
			return
		}
		dispatchContext, cancelDispatch := context.WithTimeout(parent, l.actionCeiling(parent))
		err = manager.DispatchReadyGuidance(dispatchContext)
		cancelDispatch()
		if err != nil {
			log.Printf("runtime guidance dispatch failed: %s", bounded(err.Error()))
			return
		}
		advanceContext, cancelAdvance := context.WithTimeout(parent, l.actionCeiling(parent))
		err = manager.AdvanceAutomaticRuns(advanceContext)
		cancelAdvance()
		if err != nil {
			log.Printf("runtime automatic progression failed: %s", bounded(err.Error()))
			return
		}
		pendingContext, cancelPending := context.WithTimeout(parent, l.controlPlaneTimeout)
		pending, pendingErr := manager.AutomaticWorkPending(pendingContext)
		cancelPending()
		if pendingErr != nil {
			log.Printf("runtime automatic work check failed: %s", bounded(pendingErr.Error()))
			return
		}
		if !pending {
			return
		}
		if !l.waitFor(parent, l.cadence()) {
			return
		}
	}
}

func newAccessGateway(store *state.Store, engine containers.Podman, hostKeys []model.HostKey, credential access.ControllerParentCredentialSource) (*access.Gateway, error) {
	hostKeyFingerprint, err := access.Ed25519HostKeyFingerprint(hostKeys)
	if err != nil {
		return nil, err
	}
	foremanChatQualification, err := containers.ForemanChatQualificationFromEnv(os.Getenv("WM_FOREMAN_CHAT_QUALIFICATION"))
	if err != nil {
		return nil, err
	}
	return &access.Gateway{
		Store: store, Engine: engine, SessionHandoffEngine: engine,
		ControllerPrepare:        engine,
		ControllerCredential:     credential,
		HostKeyFingerprint:       hostKeyFingerprint,
		ForemanChatQualification: foremanChatQualification,
	}, nil
}

func newRuntimeReconciler(store *state.Store, engine containers.Podman, workspaceRoot, accessPath string, sessions reconcile.Sessions, hostCapacity model.Resources, serverID, stateRoot string, managedControl control.Client, lifecycle context.Context) *reconcile.Reconciler {
	registry := continuity.StateRegistry{Store: store}
	checkpointObjects := storage.CheckpointStore{Root: filepath.Join(stateRoot, "continuity")}
	continuityService := &continuity.Service{State: store, Objects: checkpointObjects, Engine: engine, Registry: registry}
	continuityCoordinator := &continuity.Coordinator{Store: store, Service: continuityService, Helper: engine, Registry: registry}
	managedCatalog := &workspacecatalog.Catalog{State: store}
	workspaceStore := storage.Workspace{Root: workspaceRoot, Owner: "warpmetal-runtime"}
	continuationRestoreController := &continuity.S2Controller{
		Store: store, ServerID: serverID, Objects: checkpointObjects, Catalog: managedCatalog, Helper: engine,
		HandoffSupervisor: engine,
	}
	managerCoordinator := &manager.Coordinator{Store: store, Control: managedControl, Helper: engine}
	runtimeReconciler := &reconcile.Reconciler{
		Store:             store,
		Engine:            engine,
		Workspaces:        workspaceStore,
		Access:            access.Renderer{Path: accessPath},
		Sessions:          sessions,
		HostCapacity:      hostCapacity,
		ServerID:          serverID,
		Continuity:        continuityCoordinator,
		ContinuityControl: continuityCoordinator,
		ContinuityLifecycle: &continuity.CheckpointLifecycle{
			State: store, Objects: checkpointObjects, GracePeriod: time.Hour, MaxPerPass: 32,
		},
		ContinuationRestore:     continuationRestoreController,
		ContinuationHandoff:     continuationRestoreController,
		ManagedCatalog:          managedCatalog,
		ManagedControl:          managedControl,
		ManagedRuntime:          engine,
		ManagedExecutionContext: lifecycle,
		Manager:                 managerCoordinator,
	}
	continuationRestoreController.HandoffAdmission = runtimeReconciler
	runtimeReconciler.Insights = &insights.Collector{
		Store: store, Control: managedControl, Monitor: engine, Lifecycle: runtimeReconciler, Manager: managerCoordinator,
	}
	return runtimeReconciler
}

func readHostKeys() ([]model.HostKey, error) {
	paths, err := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	if err != nil {
		return nil, err
	}
	var keys []model.HostKey
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(content))
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid SSH host key %s", path)
		}
		if !supportedHostKeyAlgorithm(fields[0]) {
			continue
		}
		keys = append(keys, model.HostKey{PublicKey: fields[0] + " " + fields[1]})
	}
	if len(keys) == 0 {
		return nil, errors.New("no supported SSH host public keys were found")
	}
	return keys, nil
}

func supportedHostKeyAlgorithm(algorithm string) bool {
	switch algorithm {
	case "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return true
	default:
		return false
	}
}

func bounded(value string) string {
	if len(value) > 300 {
		return value[:300]
	}
	return value
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
