// Package workflowcontract validates the exact owner-supplied closed SOURCE
// contracts. Validation is not an approval, installed witness or activity grant.
package workflowcontract

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const Manager = "workspace-workflow-manager-v1.proposal.schema.json"
const ManagerSingle = "workspace-workflow-manager-single-v1.schema.json"
const ControllerStage = "workspace-controller-stage-v1.schema.json"
const Domain = "workspace-workflow-v1.schema.json"
const Producer = "workspace-workflow-producer-v1.schema.json"
const Lifecycle = "cell-lifecycle-v3.schema.json"
const PlanGenesis = "workspace-plan-genesis-v1.schema.json"
const ChildProduct = "workspace-child-product-v1.schema.json"
const Budget = "workspace-workflow-budget-v2.schema.json"

// Additive closed provider/controller contracts; legacy resource bytes stay pinned.
const FirstTaskProvider = "workspace-first-task-provider-v2.schema.json"
const QualificationNative = "workspace-qualification-native-v3.schema.json"

// Additive authority5 family selection: these participant-family documents and
// their pins already exist below; exposing the names here NEVER replaces or
// re-pins the legacy native-v3/provider-v2 resources.
const QualificationNativeAuthority5 = "workspace-qualification-native-v5.schema.json"
const QualificationPublicationProviderAuthority5 = "workspace-qualification-provider-v4.schema.json"
const QualificationAccessProvider = "workspace-qualification-access-v2.schema.json"
const QualificationObservationsProvider = "workspace-qualification-observations-v2.schema.json"
const ChildProvider = "workspace-child-provider-v2.schema.json"
const ChildIntegrator = "workspace-child-integrator-v1.schema.json"
const ChildReviewer = "workspace-child-reviewer-v1.schema.json"
const QualificationPublicationProvider = "workspace-qualification-provider-v2.schema.json"
const ControllerProvider = "workspace-controller-provider-v2.schema.json"
const BudgetProvider = "workspace-workflow-budget-v3.schema.json"
const ProviderOriginals = "workspace-provider-originals-v2.schema.json"
const ProviderReadback = "workspace-provider-readback-v2.schema.json"
const ProviderOriginalsMaximum = 416 * 1024
const ProviderReadbackMaximum = 512 * 1024
const ProviderAccounting = "workspace-provider-accounting-v2.schema.json"
const QualificationProvider = "agent-workspace-qualification-provider-v2.schema.json"

// Additive manager-selected LIVE window; references original Budget definitions.
// Never replaces the original or SOURCE-continuation resource/pin.
const BudgetLiveWindow = "workspace-workflow-budget-live-window-v1.schema.json"

// Byte-identical frozen F1 supplier; no locally authored private-wire schema.
const ExecutionOperatorFinancial = "workspace-test-execution-operator-financial-v1.schema.json"
const SourceLocalTransport = "workspace-source-local-transport-v1.schema.json"
const SourceLocalGrant = "workspace-source-local-grant-v1.schema.json"
const SourceLocalOriginals = "workspace-source-local-originals-v1.schema.json"
const ValidationDispatch = "workspace-validation-dispatch-v1.schema.json"
const ValidationBaselineLive = "workspace-validation-baseline-live-v1.schema.json"
const SourceOriginalMaximum = 65 * 1024
const CompleteExecutionInventory = "workspace-complete-execution-inventory-v1.schema.json"
const PaidCaseDomainAdoption = "workspace-paid-case-domain-adoption-v1.schema.json"
const PaidCaseDomainHandshake = "workspace-paid-case-domain-handshake-v1.schema.json"
const PaidCaseDomainExchange = "workspace-paid-case-domain-exchange-v1.schema.json"
const PaidCaseFinancialOriginalIndex = "workspace-paid-case-financial-original-index-v1.schema.json"
const FinancialOriginalIndexMaximum = 512 * 1024

// Exact approved eight-delta SOURCE13 branch. Its raw $id is unchanged, so it
// MUST use a separate compiler resource family, never replace the LIVE resource.
const BudgetSourceContinuation = "workspace-workflow-budget-v2.source-continuation.schema.json"
const budgetSourceContinuationSHA256 = "e2b48556a7f27a5d85a2acf32ef981393cd629a64348114fd3a447c0baac05ea"

// Supplier byte captures, not locally edited schema forks. All external refs are
// satisfied from this pinned closure; no URLLoader/network fallback exists.
//
//go:embed schema/*.json schema/participants/*.json
var supplier embed.FS

var pins = map[string]string{
	ControllerStage:                   "1600a48eb1276dbd8b4df5f4e7015ddc530c630f84848a5270ea981e6d9f3435",
	ManagerSingle:                     "7fe8cf8b4eba140c0019a58367e11a03458886720f432755fc3fad2f7c0739cb",
	QualificationObservationsProvider: "28ab5f38ee81c7a790c5a5ed474004c23e72885f42d94010c335c6d0f015d26e",
	QualificationAccessProvider:       "6f299561a19e35b6c4c8575a9f2a9f8307cfdffbedf27a3581e015a2ae0a499c",
	QualificationNative:               "8cf28601c51cf356596d4f7f970b4280143e109ad8f438bfb445392754a26edc",
	FirstTaskProvider:                 "48f799cbf635800c335489c3583d5e2a51f8e5beaf596d2bb0c82ad8612fcfb3",
	ProviderOriginals:                 "ccdb3af4a016d69ffa574a4609d3f2496e93f050c1af7a63e2b0c51ad119f38f",
	ProviderReadback:                  "93af6e84491548f07a6e5e6ff33808ac12d16ff73359037215247da135d14016",
	ChildProvider:                     "8a741172a3b1ab86738ada4e66062f4bc99ed9e968f5b66c206c8bcebd146532",
	ChildIntegrator:                   "7a05be5f6af976d76e6b68495c6c31d10660348787dd62e5ea81525183e6062c",
	ChildReviewer:                     "001af7e4e908618dd93edddfae16ebc3c5d62f1f2864f20df8c7d64fc0dd2254",
	QualificationPublicationProvider:  "55c7427a1016aac787026735b9b93f2a7eff1bec335244c1812c69af346a045f",
	ControllerProvider:                "63cdd77812bf73258a25f4aa6e32296185a3698abfb6d9bb549c74967f821ed3",
	BudgetProvider:                    "e4e6850d744296937d1d5609f9738f2c8f3ade7cf3d0c3402cfa9198cdd4e130",
	ProviderAccounting:                "5c7e2e1e4296a003ce89504449fc9e4d0253f6cf6ef181f878f2fe88c1705d35",
	QualificationProvider:             "f07573a60a052dbdca90d689df470ce4793bb86192bb00d9f094ea1cb691efce",
	ExecutionOperatorFinancial:        "b0cb8e1a6161f785ece92ed698618aca698054f9ce5c4861e6e1fdae22e3ddfb",
	PaidCaseFinancialOriginalIndex:    "3ec5a9bebc1e24f1ab22a8127d567b950e54b3a70462177cbc98f62e4ddf93b3",
	SourceLocalOriginals:              "4e8732f18a2ef30a5e3ea0689611c0e906ac7640def6832e93c8730692cae1b6",
	ValidationDispatch:                "4c2936eed4a7c3ef2b5abcdb3b8b75c592501721d0020ff4c95413efa924d341",
	ValidationBaselineLive:            "72adb1be9428089ef7ef821a82afa6aa889b9bde965ddf4e989b87b968da7084",
	PaidCaseDomainExchange:            "5788bf1ee5def199b9a1d6a23bd4cbf18d5d25107d2b907cd7dd6331c26c393b",
	PaidCaseDomainHandshake:           "3d124024f65b953fe418d65f815100213b7b399d3d57ea6a4a40582c8c867f0e",
	CompleteExecutionInventory:        "9fce58c8bcaf3d16b37b80f759b427c2a2da091d9e5e2f456db1946a80e2a0cb",
	PaidCaseDomainAdoption:            "d7a6ff7cf096d8a89a2890b472cef54a869caa052f3ddd7b45679b994d960a07",
	SourceLocalGrant:                  "57d1636fe3fb74e15ad1ae3ab263157559e2b7c6480eeaa77a5c4c15cb057117",
	SourceLocalTransport:              "7c5bb10ec9df270ca82a9e14df2956063911f8e186436d84e91f01a336662745",
	BudgetLiveWindow:                  "343f97d557638184ce495d68b0f7dae08f06160a8ef96390a7678b1105585693",
	Budget:                            "389206ceed518078af6ab324ed8edf6addb7b265471f139ccdc0585daf1447d2",
	ChildProduct:                      "8c73c2ff78ffaa2160246560c94ad25567d8b42833a896cdd8a740a554f907f4",
	PlanGenesis:                       "d052c5d863703645b4b7f395b2eb7a4fad0e544ebd9bf0b6f90ea62a3f7467aa",
	Manager:                           "1ff7c6b301eea395031c7c8acdc91bf7f131e08cc26503866fe06a141bb29459",
	Domain:                            "13e5a8eea6a97698c8e57a29c734ace8d309c6d07d96cd3da6dd40c89273ef34",
	Producer:                          "60bf59da8175cf0e6aad2b282963bb43ff01ab06125f728958bf972dd80ff4af",
	Lifecycle:                         "c3ae13167db27c13953da6ba608f18c6a7b6ef6137db1fa120287a9a172e05b7",
	"agent-workspace-configuration-v1.schema.json": "182733ba61fe96d97a9aaf4a727409c866649014a172ac190d6654d0180cf73c",
	"agent-workspace-configuration-v2.schema.json": "31fbbd96386e7bcce4c0ed89bcae82fb4b9730574ae8876a72e56d4178a448f6",
}

// SupplierSHA256 returns the authoritative raw-byte pin, not a current backend
// checkout's proposal or a mutable consumer claim. Unknown documents return "".
func SupplierSHA256(document string) string {
	if document == BudgetSourceContinuation {
		return budgetSourceContinuationSHA256
	}
	if participantDocuments[document] {
		return participantPins[document]
	}
	return pins[document]
}

type boundedRegexp struct{ *regexp2.Regexp }

func (r boundedRegexp) MatchString(s string) bool {
	ok, err := r.Regexp.MatchString(s)
	return err == nil && ok
}

type contractCache struct {
	sync.Mutex
	compiler *jsonschema.Compiler
	ids      map[string]string
	schemas  map[string]*jsonschema.Schema
}

var cache contractCache
var sourceContinuationCache contractCache
var participantCache contractCache

func selected(document, definition string) (*jsonschema.Schema, error) {
	selectedCache := &cache
	participantFamily := participantDocuments[document]
	if participantFamily {
		selectedCache = &participantCache
	}
	if document == BudgetSourceContinuation {
		selectedCache = &sourceContinuationCache
	}
	cache := selectedCache
	cache.Lock()
	defer cache.Unlock()
	if SupplierSHA256(document) == "" || definition == "" {
		return nil, errors.New("unselected workflow contract")
	}
	if cache.compiler == nil {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
			r, err := regexp2.Compile(pattern, regexp2.ECMAScript)
			if err != nil {
				return nil, err
			}
			r.MatchTimeout = 50 * time.Millisecond
			return boundedRegexp{r}, nil
		})
		ids := map[string]string{}
		resources, directory := pins, "schema/"
		if participantFamily {
			resources, directory = participantPins, "schema/participants/"
		}
		for filename, pin := range resources {
			capture := filename
			if document == BudgetSourceContinuation && filename == Budget {
				capture, pin = BudgetSourceContinuation, budgetSourceContinuationSHA256
			}
			raw, err := supplier.ReadFile(directory + capture)
			if err != nil {
				return nil, err
			}
			digest := sha256.Sum256(raw)
			if hex.EncodeToString(digest[:]) != pin {
				return nil, errors.New("workflow supplier pin mismatch")
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return nil, err
			}
			id, ok := doc.(map[string]any)["$id"].(string)
			if !ok {
				return nil, errors.New("workflow supplier has no identity")
			}
			if err := compiler.AddResource(id, doc); err != nil {
				return nil, err
			}
			ids[filename] = id
			if document == BudgetSourceContinuation && filename == Budget {
				ids[BudgetSourceContinuation] = id
			}
		}
		cache.compiler, cache.ids, cache.schemas = compiler, ids, map[string]*jsonschema.Schema{}
	}
	fragment := "#/$defs/" + definition
	if (document == ProviderParticipantReadback || document == ProviderReadback || document == QualificationAccessProvider || document == QualificationObservationsProvider) && definition == "#" {
		fragment = "#"
	}
	key := document + fragment
	if schema := cache.schemas[key]; schema != nil {
		return schema, nil
	}
	schema, err := cache.compiler.Compile(cache.ids[document] + fragment)
	if err != nil {
		return nil, err
	}
	cache.schemas[key] = schema
	return schema, nil
}

// Validate enforces closed owner fields and the protocol's strict UTF-8, unique
// JSON and safe integer rules before decoding into a consumer representation.
// Callers must still independently join signatures/current protected facts.
func Validate(document, definition string, raw []byte) error {
	return validateBounded(document, definition, raw, 65536)
}

// These bounded owner transports preserve whole signed originals. A backend
// prefix is an observation, never an independently observed Runtime ledger cut.
// Exactly versioned owner first-task families; a rejected legacy original is
// never reinterpreted as successor authority.
func ValidateOwnerFirstTask(definition string, raw []byte) error {
	if definition != "ownerFirstTaskOriginal" && definition != "ownerFirstTaskResponse" {
		return errors.New("unselected owner first-task contract")
	}
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &version) != nil {
		return errors.New("invalid first-task JSON")
	}
	if version.FormatVersion == 2 {
		return Validate(FirstTaskProvider, definition+"2", raw)
	}
	return Validate(Producer, definition, raw)
}
func ValidateQualificationAccessProvider(raw []byte) error {
	return validateBounded(QualificationAccessProvider, "#", raw, 65536)
}
func ValidateQualificationObservationsProvider(raw []byte) error {
	return validateBounded(QualificationObservationsProvider, "#", raw, 2*1024*1024)
}

func ValidateProviderReadback(raw []byte) error {
	if wireVersion(raw) == 3 {
		return validateBounded(ProviderParticipantReadback, "#", raw, ProviderReadbackMaximum)
	}
	return validateBounded(ProviderReadback, "#", raw, ProviderReadbackMaximum)
}
func ValidateProviderOriginals(raw []byte) error {
	if wireVersion(raw) == 3 {
		return validateBounded(ProviderParticipantOriginals, "originalSettlement", raw, ProviderOriginalsMaximum)
	}
	return validateBounded(ProviderOriginals, "originalSettlement", raw, ProviderOriginalsMaximum)
}

// Only the manager-selected private SOURCE-owning-original wire has this cap.
// Ordinary/native/physical facts and all previous schemas retain their limits.
func ValidateSourceOriginal(definition string, raw []byte) error {
	return validateBounded(SourceLocalOriginals, definition, raw, SourceOriginalMaximum)
}

func ValidateFinancialOriginalIndex(raw []byte) error {
	return validateBounded(PaidCaseFinancialOriginalIndex, "financialOriginalIndexEnvelope", raw, FinancialOriginalIndexMaximum)
}

// 09:33 exchange only. No ordinary/native wire or per-original cap is enlarged.
func ValidatePaidObservation(raw []byte) error {
	return validateBounded(PaidCaseDomainExchange, "observationRequest", raw, 16*1024*1024)
}

// r41 private metadata cap only; no ordinary authority/grant wire is enlarged.
func ValidateSourceTransportControl(raw []byte) error {
	return validateBounded(SourceLocalTransport, "control", raw, 512*1024)
}

// Additive r42/r43 SOURCE owner family. Selection is internal and explicit;
// native/ordinary LIVE decoders keep their original closed schemas and limits.
func ValidateSourceLocalGrant(definition string, raw []byte) error {
	return validateBounded(SourceLocalGrant, definition, raw, 512*1024)
}

// Explicit new F1 finite control limits; no ordinary/legacy wire is enlarged.
// Schema document identity disambiguates FULL productPolicyEnvelope from the
// revision13 envelope of that name which signs only productPolicyBinding.
func ValidateChildProduct(definition string, raw []byte) error {
	return validateChildProductDocument(ChildProduct, definition, raw)
}

// Explicit family selection; never retry a rejected revision14 wire as revision13.
func ValidateChildProductVersion(version int, definition string, raw []byte) error {
	if version == 5 {
		if definition != "controlDelivery" && definition != "controlGeneration" {
			return errors.New("unselected reviewer control contract")
		}
		return ValidateChildReviewer(definition, raw)
	}
	if version == 4 {
		if definition != "controlDelivery" && definition != "controlGeneration" {
			return errors.New("unselected integrator control contract")
		}
		return ValidateChildIntegrator(definition, raw)
	}
	if version == 3 {
		return validateChildProductDocument(ChildProvider, definition, raw)
	}
	if version == 1 {
		return ValidateChildProduct(definition, raw)
	}
	if version != 2 {
		return errors.New("unsupported child product generation")
	}
	return validateChildProductDocument(Budget, definition, raw)
}

// The independent integrator has its own additive document and publication
// versions. It never changes the meaning of legacy publication version3.
func ValidateChildIntegrator(definition string, raw []byte) error {
	limit := 65536
	switch definition {
	case "controlDelivery", "controlGeneration", "selectedControlDelivery", "selectedControlGeneration", "baseControlGeneration":
		limit = 512 * 1024
	case "productPolicy", "productPolicyEnvelope", "policySigningIntent", "policyAcceptRequest", "baseProductPolicy", "selectedProductPolicy", "integrationDelivery", "installedInputs", "installedInputObservation", "installedInputEnvelope":
		limit = 256 * 1024
	case "integrationSourceGrant", "integrationReadRoot", "integrationSourceScope", "integrationByteSpan":
	default:
		return errors.New("unselected child integrator contract")
	}
	return validateBounded(ChildIntegrator, definition, raw, limit)
}

// Immutable reviewer artifacts use an additive owner document. A publication's
// version alone never widens the meaning of existing child policy contracts.
func ValidateChildReviewer(definition string, raw []byte) error {
	limit := 65536
	switch definition {
	case "controlDelivery", "controlGeneration":
		limit = 512 * 1024
	case "productPolicy", "productPolicyEnvelope", "reviewDeliveryPlan", "installedInputs", "installedInputObservation", "installedInputEnvelope":
		limit = 256 * 1024
	case "physicalSourceScope", "artifactAuthority":
	default:
		return errors.New("unselected child reviewer contract")
	}
	return validateBounded(ChildReviewer, definition, raw, limit)
}

// Child publication messages have their own version, distinct from control
// generation1/2/3. Select once; a refused legacy original is never retried as a
// successor. Signatures and current owner/case joins remain the caller's work.
func ValidateChildPublication(definition string, raw []byte) error {
	switch definition {
	case "policySigningIntent", "policyAcceptRequest", "activationSigningIntent", "activationAcceptRequest", "grantIntent":
	default:
		return errors.New("unselected child publication contract")
	}
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &version) != nil {
		return errors.New("invalid child publication JSON")
	}
	document := Budget
	switch version.FormatVersion {
	case 1:
	case 2:
		document = ChildProvider
	default:
		return errors.New("unsupported child publication version")
	}
	return Validate(document, definition, raw)
}

// Parsing under this branch is NOT SOURCE authority. Owning consumers must join
// the independently selected SOURCE config/continuation and original signature.
func ValidateChildProductSourceContinuation(version int, definition string, raw []byte) error {
	if version != 2 {
		return errors.New("SOURCE continuation requires child generation2")
	}
	return validateChildProductDocument(BudgetSourceContinuation, definition, raw)
}

func validateChildProductDocument(document, definition string, raw []byte) error {
	limit := 65536
	switch definition {
	case "controlDelivery", "controlGeneration":
		limit = 512 * 1024
	case "preparationPolicy", "preparationPolicyEnvelope", "productPolicy", "productPolicyEnvelope", "policyAcceptRequest", "policySigningIntent":
		limit = 256 * 1024
	case "controlDescriptor", "effectControl", "authorizationObservation", "authorizationEnvelope", "activation", "activationEnvelope", "grantIntent", "activationIntentRequest", "activationSigningIntent", "activationAcceptRequest", "activationAcceptReceipt", "policyAcceptReceipt", "publicationReceipt":
	default:
		return errors.New("unselected child product contract")
	}
	return validateBounded(document, definition, raw, limit)
}

// Sole new finite full-byte source report, not a domain-wide wire enlargement.
func ValidatePlanRead(definition string, raw []byte) error {
	switch definition {
	case "readback", "readPayload", "readEnvelope":
	default:
		return errors.New("unselected full-byte plan report")
	}
	return validateBounded(PlanGenesis, definition, raw, 1<<20)
}

func validateBounded(document, definition string, raw []byte, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || !validSurrogates(raw) {
		return errors.New("invalid workflow JSON bytes")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := uniqueValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing workflow JSON")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	schema, err := selected(document, definition)
	if err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return errors.New("closed workflow schema refused")
	}
	return nil
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("workflow JSON depth exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if n, ok := t.(json.Number); ok {
		// The typed wire uses integers, not exponent/float coercions. Int64 also
		// avoids unbounded big-number allocation on a hostile exponent token.
		integer, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil || integer < -9007199254740991 || integer > 9007199254740991 {
			return errors.New("unsafe workflow number")
		}
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate workflow key")
			}
			seen[name] = true
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unclosed workflow object")
		}
	case json.Delim('['):
		for d.More() {
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unclosed workflow array")
		}
	default:
		if _, ok := t.(json.Delim); ok {
			return fmt.Errorf("unexpected workflow delimiter")
		}
	}
	return nil
}

// encoding/json otherwise silently replaces lone escaped surrogates. Scan only
// actual string escapes; a literal escaped backslash is not a Unicode escape.
func validSurrogates(raw []byte) bool {
	inside := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inside
}
