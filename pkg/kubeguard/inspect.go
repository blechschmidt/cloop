package kubeguard

// inspect.go reads what a write asks the cluster to store, for the few kinds of
// object whose *content* decides whether a sandbox walks away with a credential
// of its own (Task 20420).
//
// Everything else in the monitor decides on the tuple apirequest.go produces —
// verb, resource, namespace — and that is enough for every rule a grant can
// state. It is not enough for this one. A grant that may write a namespace
// holds `create` on secrets and pods, and three of the objects that verb
// creates are credentials in all but name:
//
//   - a Secret of type kubernetes.io/service-account-token, which the cluster
//     fills in with a non-expiring token for whichever ServiceAccount the
//     Secret's annotation names;
//   - a Pod — or anything that stamps Pods out of a template: a Job, a
//     Deployment, a CronJob — running as a ServiceAccount other than the
//     namespace's default, whose token the cluster mounts into the container,
//     where the workload prints it to its log and reads the log back;
//   - a Pod that reaches the node itself — host namespaces, a privileged
//     container, a hostPath volume — where every other Pod's token, and the
//     kubelet's own credential, sit on disk.
//
// Each of those is a credential that never passes through this monitor again,
// that no grant's TTL bounds, and that a revocation does not reach. The verb
// check cannot tell them apart from a ConfigMap, so the body is read: create,
// update and patch of these kinds are refused when they would produce one.
//
// Two more kinds are refused without reading anything, in policy.go's Decide:
// RBAC (a RoleBinding granting the namespace's default ServiceAccount more is
// the same escalation with one more step) and CertificateSigningRequests (a
// client certificate is a credential the monitor never sees). And the
// ephemeralcontainers subresource joins the dangerous ones: it starts a new
// process inside a Pod that already runs as some other ServiceAccount.
//
// # Fail closed on what cannot be read
//
// The API server accepts protobuf and CBOR as well as JSON and YAML, and a
// monitor that only understood JSON would wave a protobuf Pod through unread.
// So for the kinds inspected here, a body the monitor cannot decode — an
// encoding it does not speak, a compressed body, malformed JSON — is refused
// rather than forwarded. kubectl, Helm and client-go's defaults all send JSON.
//
// # Read every occurrence, not the last one
//
// A JSON object may repeat a key, and decoders disagree about which copy wins.
// The JSON walk below therefore visits every key-value pair in the document,
// duplicates included, and refuses if *any* of them is a credential — so a
// difference between this decoder and the API server's cannot be turned into
// a bypass by sending the harmless value first and the dangerous one second.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Denial reasons added by this file. Each is its own metric label and audit
// reason, so an operator can tell "a chart tried to create a token Secret"
// from "a workload tried to run as the deployer's ServiceAccount".
const (
	// DenyServiceAccountTokenSecret: a write of a Secret of type
	// kubernetes.io/service-account-token, or one touching the annotations
	// that point such a Secret at a ServiceAccount.
	DenyServiceAccountTokenSecret DenyReason = "service_account_token_secret"
	// DenyWorkloadServiceAccount: a workload — a Pod, or anything with a Pod
	// template — that would run as a ServiceAccount other than the
	// namespace's default, or a change to one that already does.
	DenyWorkloadServiceAccount DenyReason = "workload_service_account"
	// DenyHostAccess: a workload that would reach the node — host namespaces,
	// a privileged container, a hostPath volume — or a change to one that
	// already does.
	DenyHostAccess DenyReason = "host_access"
	// DenyRBACBinding: a write to a RoleBinding or ClusterRoleBinding.
	DenyRBACBinding DenyReason = "rbac_binding"
	// DenyRBACRole: a write to a Role or ClusterRole.
	DenyRBACRole DenyReason = "rbac_role"
	// DenyCertificateSigningRequest: a write to a CertificateSigningRequest,
	// including its approval and status.
	DenyCertificateSigningRequest DenyReason = "certificate_signing_request"
	// DenyUnreadableBody: a write the monitor has to read before forwarding,
	// in an encoding it cannot read.
	DenyUnreadableBody DenyReason = "unreadable_body"
)

// The API groups this file names.
const (
	rbacGroup         = "rbac.authorization.k8s.io"
	certificatesGroup = "certificates.k8s.io"
)

// serviceAccountTokenType is the Secret type the token controller fills in.
const serviceAccountTokenType = "kubernetes.io/service-account-token"

// serviceAccountSecretMarkers are the strings whose presence in a Secret
// write makes it a token Secret, or re-points one: the type, and the two
// annotations that name the ServiceAccount (kubernetes.io/service-account.name
// and .uid). Matched as substrings, after JSON-pointer unescaping, anywhere in
// the body — a key, a value, or a JSON-patch path.
var serviceAccountSecretMarkers = []string{
	serviceAccountTokenType,
	"kubernetes.io/service-account.",
}

// workloadResources are the built-in resources that run Pods: a Pod itself,
// and every controller that stamps Pods out of a template. Keyed by
// "group/resource", with "" as the core group.
var workloadResources = map[string]bool{
	"/pods":                             true,
	"/podtemplates":                     true,
	"/replicationcontrollers":           true,
	"apps/deployments":                  true,
	"apps/replicasets":                  true,
	"apps/statefulsets":                 true,
	"apps/daemonsets":                   true,
	"batch/jobs":                        true,
	"batch/cronjobs":                    true,
	"extensions/deployments":            true,
	"extensions/replicasets":            true,
	"extensions/daemonsets":             true,
	"extensions/podtemplates":           true,
	"extensions/statefulsets":           true,
	"extensions/replicationcontrollers": true,
}

// builtinGroups are the API groups the API server serves itself. Anything else
// is a custom resource or an aggregated API, whose schema this monitor cannot
// know — and several of which (Tekton's TaskRuns, Argo's Workflows, Flux's
// Kustomizations) name a ServiceAccount to act as, which is the same
// escalation as a Pod naming one.
//
// Named one by one, not matched by the ".k8s.io" suffix: a
// CustomResourceDefinition may claim a group under k8s.io too (the Gateway
// API's, a SIG project's), and a custom resource there is as unknown as any
// other. A group a later Kubernetes release adds is read as a custom one until
// it is listed here, which costs a write to it a body check, not a hole.
var builtinGroups = map[string]bool{
	"":                             true,
	"apps":                         true,
	"batch":                        true,
	"autoscaling":                  true,
	"policy":                       true,
	"extensions":                   true,
	"admissionregistration.k8s.io": true,
	"apiextensions.k8s.io":         true,
	"apiregistration.k8s.io":       true,
	"authentication.k8s.io":        true,
	"authorization.k8s.io":         true,
	"certificates.k8s.io":          true,
	"coordination.k8s.io":          true,
	"discovery.k8s.io":             true,
	"events.k8s.io":                true,
	"flowcontrol.apiserver.k8s.io": true,
	"internal.apiserver.k8s.io":    true,
	"networking.k8s.io":            true,
	"node.k8s.io":                  true,
	"rbac.authorization.k8s.io":    true,
	"resource.k8s.io":              true,
	"scheduling.k8s.io":            true,
	"storage.k8s.io":               true,
	"storagemigration.k8s.io":      true,
}

// builtinGroup reports whether group is one of the API server's own.
func builtinGroup(group string) bool { return builtinGroups[group] }

// isReadOnlyVerb reports the three verbs that cannot change the cluster.
func isReadOnlyVerb(v string) bool { return isReadVerb(v) }

// credentialResourceDenial refuses the writes that hand out authority without
// any body to read: RBAC objects and CertificateSigningRequests. A read of
// either is left to the ordinary checks.
//
// Refused for every write verb, delete included: the monitor is not where a
// cluster's access control is administered, and allowing "only the harmless
// RBAC writes" would mean deciding which ones those are.
func credentialResourceDenial(r APIRequest) *Denial {
	if !r.IsResource || isReadOnlyVerb(r.Verb) {
		return nil
	}
	switch {
	case r.APIGroup == rbacGroup && (r.Resource == "rolebindings" || r.Resource == "clusterrolebindings"):
		return &Denial{
			Reason: DenyRBACBinding,
			Message: fmt.Sprintf(
				"%s %s is refused by the cloop Kubernetes monitor under every grant: a binding hands "+
					"some ServiceAccount authority — the namespace's default one, say, which any Pod "+
					"runs as — that its workloads would then hold outside this monitor. Ask a cluster "+
					"administrator to manage RBAC",
				r.Verb, r.ResourceString()),
		}
	case r.APIGroup == rbacGroup && (r.Resource == "roles" || r.Resource == "clusterroles"):
		return &Denial{
			Reason: DenyRBACRole,
			Message: fmt.Sprintf(
				"%s %s is refused by the cloop Kubernetes monitor under every grant: changing a role "+
					"changes what every subject already bound to it may do, outside this monitor. Ask a "+
					"cluster administrator to manage RBAC",
				r.Verb, r.ResourceString()),
		}
	case r.APIGroup == certificatesGroup && r.Resource == "certificatesigningrequests":
		return &Denial{
			Reason: DenyCertificateSigningRequest,
			Message: fmt.Sprintf(
				"%s %s is refused by the cloop Kubernetes monitor under every grant: a signed "+
					"certificate is a credential for the cluster that would never pass through this "+
					"monitor again",
				r.Verb, r.ResourceString()),
		}
	}
	return nil
}

// bodyRules is what a write's body is checked for.
type bodyRules struct {
	// tokenSecret: the Secret must not be, or become, a ServiceAccount token.
	tokenSecret bool
	// serviceAccount: nothing in it may name a ServiceAccount other than the
	// namespace's default.
	serviceAccount bool
	// hostAccess: no Pod template in it may reach the node.
	hostAccess bool
	// stored: a patch is checked against the object it patches as well,
	// which the monitor reads first — a patch keeps every field it does not
	// mention, including the ServiceAccount and the volumes.
	stored bool
}

func (b bodyRules) any() bool { return b.tokenSecret || b.serviceAccount || b.hostAccess }

// rulesFor reports which checks a request's body gets. Only writes to a
// resource itself are inspected: a subresource's body (a Scale, a Status, an
// Eviction) cannot change who a workload runs as, and the subresources that
// could are refused outright as dangerous.
func rulesFor(r APIRequest) bodyRules {
	if !r.IsResource || r.Subresource != "" {
		return bodyRules{}
	}
	switch r.Verb {
	case VerbCreate, VerbUpdate, VerbPatch:
	default:
		return bodyRules{}
	}
	var b bodyRules
	switch {
	case r.APIGroup == "" && r.Resource == "secrets":
		b.tokenSecret = true
	case workloadResources[r.APIGroup+"/"+r.Resource]:
		b.serviceAccount, b.hostAccess = true, true
	case !builtinGroup(r.APIGroup):
		b.serviceAccount = true
	}
	b.stored = r.Verb == VerbPatch && (b.serviceAccount || b.hostAccess)
	return b
}

// NeedsBody reports whether Decide's verdict on r is provisional until its
// body has been read with InspectWrite.
func NeedsBody(r APIRequest) bool { return rulesFor(r).any() }

// bodyFormat is how a write's body is encoded.
type bodyFormat int

const (
	// formatJSON is one JSON value: an object for a create or update, a
	// merge or strategic-merge patch.
	formatJSON bodyFormat = iota
	// formatJSONPatch is an RFC 6902 list of operations.
	formatJSONPatch
	// formatYAML is a YAML document: a create or update sent as YAML, or a
	// server-side apply.
	formatYAML
)

// bodyFormatOf maps a write's Content-Type onto a format this file can read.
// ok is false for everything else — protobuf, CBOR, anything unknown — which
// the caller refuses.
//
// A create or update with no Content-Type is JSON: the API server negotiates
// an empty one as its first supported type, which is JSON. A patch with none
// is refused by the API server, so it is refused here too.
func bodyFormatOf(verb, contentType string) (bodyFormat, bool) {
	mediaType := ""
	if strings.TrimSpace(contentType) != "" {
		mt, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return 0, false
		}
		mediaType = strings.ToLower(mt)
	}
	if verb == VerbPatch {
		switch mediaType {
		case "application/merge-patch+json", "application/strategic-merge-patch+json":
			return formatJSON, true
		case "application/json-patch+json":
			return formatJSONPatch, true
		case "application/apply-patch+yaml":
			return formatYAML, true
		}
		return 0, false
	}
	switch mediaType {
	case "", "application/json":
		return formatJSON, true
	case "application/yaml":
		return formatYAML, true
	}
	return 0, false
}

// maxInspectDepth bounds how deeply a body nests before it is refused as
// unreadable. No Kubernetes object comes near it, and the walk is recursive.
const maxInspectDepth = 512

// errTooDeep is a body nested past maxInspectDepth.
var errTooDeep = errors.New("the body nests deeper than the monitor reads")

// InspectWrite decides a write whose verdict NeedsBody said was provisional.
// It returns nil when the body may be forwarded, or a *Denial.
//
// contentEncoding is the request's Content-Encoding: a compressed body is not
// one the monitor can read, so anything but identity is refused.
func InspectWrite(r APIRequest, contentType, contentEncoding string, body []byte) error {
	rules := rulesFor(r)
	if !rules.any() {
		return nil
	}
	if enc := strings.ToLower(strings.TrimSpace(contentEncoding)); enc != "" && enc != "identity" {
		return unreadable(r, fmt.Sprintf("the body is %s-encoded", enc))
	}
	format, ok := bodyFormatOf(r.Verb, contentType)
	if !ok {
		ct := strings.TrimSpace(contentType)
		if ct == "" {
			ct = "no Content-Type"
		}
		return unreadable(r, fmt.Sprintf("it is sent as %s", ct))
	}
	sc := &scanner{rules: rules, req: r}
	var err error
	switch format {
	case formatJSON:
		err = walkJSON(body, sc.visit)
	case formatJSONPatch:
		err = sc.jsonPatch(body)
	case formatYAML:
		err = walkYAML(body, sc.visit)
	}
	if sc.denial != nil {
		return sc.denial
	}
	if err != nil {
		return unreadable(r, err.Error())
	}
	return nil
}

// InspectStored decides a patch against the object it would patch, as the API
// server holds it now. A patch keeps every field it does not mention, so a
// harmless-looking change of image to a Deployment that runs as the deployer's
// ServiceAccount is a workload of the attacker's choosing running as the
// deployer.
func InspectStored(r APIRequest, stored []byte) error {
	rules := rulesFor(r)
	if !rules.stored {
		return nil
	}
	sc := &scanner{rules: bodyRules{serviceAccount: rules.serviceAccount, hostAccess: rules.hostAccess},
		req: r, stored: true}
	err := walkJSON(stored, sc.visit)
	if sc.denial != nil {
		return sc.denial
	}
	if err != nil {
		return unreadable(r, "the object it patches could not be read: "+err.Error())
	}
	return nil
}

func unreadable(r APIRequest, why string) *Denial {
	return &Denial{
		Reason: DenyUnreadableBody,
		Message: fmt.Sprintf(
			"%s %s is refused: the cloop Kubernetes monitor reads every write of this kind before it "+
				"reaches the cluster, and cannot read this one (%s). Send JSON — kubectl, Helm and "+
				"client-go do by default",
			r.Verb, r.ResourceString(), why),
	}
}

// scanner applies bodyRules to the key-value pairs of one document and keeps
// the first denial it meets.
type scanner struct {
	rules  bodyRules
	req    APIRequest
	stored bool
	denial *Denial
}

// The walk's view of a container: visit sees these where a value is an
// object or an array, before it descends into it.
type (
	jsonObject struct{}
	jsonArray  struct{}
)

// hostAccessKeys are the PodSpec and SecurityContext fields that reach the
// node, and are checked for any value other than false. Any other value is
// refused, not just true: YAML 1.1 — which the API server's YAML decoder
// speaks — reads "yes" and "on" as true, where this file's YAML 1.2 decoder
// reads them as strings.
var hostAccessKeys = map[string]string{
	"hostpid":     "the node's process namespace (hostPID)",
	"hostipc":     "the node's IPC namespace (hostIPC)",
	"hostnetwork": "the node's network namespace (hostNetwork)",
	"privileged":  "a privileged container",
}

// visit checks one key-value pair. key is the key the value sits under — the
// array's key for an array element, "" at the top — and v is a string,
// json.Number, bool, nil, jsonObject or jsonArray.
func (s *scanner) visit(key string, v any) error {
	if s.denial != nil {
		return nil
	}
	lower := strings.ToLower(key)
	if s.rules.tokenSecret {
		str, _ := v.(string)
		if hit := tokenSecretMarker(key, str); hit != "" {
			s.deny(DenyServiceAccountTokenSecret, fmt.Sprintf(
				"%s %s is refused by the cloop Kubernetes monitor: it mentions %q, which makes a Secret "+
					"a ServiceAccount token the cluster fills in — a credential that would never pass "+
					"through this monitor again, and that no revocation reaches",
				s.req.Verb, s.req.ResourceString(), hit))
			return nil
		}
	}
	if s.rules.serviceAccount && (lower == "serviceaccountname" || lower == "serviceaccount") {
		switch val := v.(type) {
		case nil, jsonObject, jsonArray:
			// Not a name. An object under "serviceAccount" is some custom
			// resource's own shape, which this monitor does not know.
		case string:
			if val != "" && val != "default" {
				s.denyServiceAccount(key, val)
				return nil
			}
		default:
			// A number or a boolean is no ServiceAccount name; the API server
			// would refuse it, and so does this.
			s.denyServiceAccount(key, fmt.Sprint(val))
			return nil
		}
	}
	if s.rules.hostAccess {
		if what, ok := hostAccessKeys[lower]; ok {
			if b, isBool := v.(bool); !(isBool && !b) && v != nil {
				s.denyHost(what)
				return nil
			}
		}
		if lower == "hostpath" && v != nil {
			s.denyHost("a hostPath volume")
			return nil
		}
	}
	return nil
}

// tokenSecretMarker returns the marker key or value carries, or "".
func tokenSecretMarker(key, value string) string {
	for _, s := range []string{key, value} {
		if s == "" {
			continue
		}
		// A JSON-patch path writes "/" inside a key as "~1".
		unescaped := strings.ReplaceAll(s, "~1", "/")
		for _, m := range serviceAccountSecretMarkers {
			if strings.Contains(unescaped, m) {
				return m
			}
		}
	}
	return ""
}

func (s *scanner) deny(reason DenyReason, msg string) {
	if s.denial == nil {
		s.denial = &Denial{Reason: reason, Message: msg}
	}
}

func (s *scanner) denyServiceAccount(key, name string) {
	if s.stored {
		s.deny(DenyWorkloadServiceAccount, fmt.Sprintf(
			"%s %s is refused by the cloop Kubernetes monitor: the object already runs as ServiceAccount "+
				"%q (%s), and a patch keeps that, so whatever the patch changes would run with that "+
				"ServiceAccount's token — a credential outside this monitor. Only workloads running as "+
				"the namespace's default ServiceAccount may be changed through it",
			s.req.Verb, s.req.ResourceString(), name, key))
		return
	}
	s.deny(DenyWorkloadServiceAccount, fmt.Sprintf(
		"%s %s is refused by the cloop Kubernetes monitor: it names ServiceAccount %q (%s), whose token "+
			"the cluster would hand the workload — a credential outside this monitor, which no revocation "+
			"reaches. Workloads created through it run as the namespace's default ServiceAccount",
		s.req.Verb, s.req.ResourceString(), name, key))
}

func (s *scanner) denyHost(what string) {
	if s.stored {
		s.deny(DenyHostAccess, fmt.Sprintf(
			"%s %s is refused by the cloop Kubernetes monitor: the object already uses %s, and a patch "+
				"keeps that — on the node sit every Pod's ServiceAccount token and the kubelet's own "+
				"credential",
			s.req.Verb, s.req.ResourceString(), what))
		return
	}
	s.deny(DenyHostAccess, fmt.Sprintf(
		"%s %s is refused by the cloop Kubernetes monitor: it asks for %s, which reaches the node — where "+
			"every Pod's ServiceAccount token and the kubelet's own credential sit, outside this monitor",
		s.req.Verb, s.req.ResourceString(), what))
}

// jsonPatch inspects an RFC 6902 patch. The operations are decoded the way the
// API server's json-patch library decodes them — a map per operation, so a
// repeated key's last copy is the one applied — and each is checked by what it
// writes where:
//
//   - its path, from and string value against the token-Secret markers;
//   - a value written at a path ending in a checked field ("/spec/
//     serviceAccountName", "/spec/hostPID", ".../hostPath") as that field;
//   - an object value walked whole, under its path's last segment;
//   - copy and move refused on the workload kinds, since what they write
//     comes from elsewhere in the object and cannot be judged from the patch.
func (s *scanner) jsonPatch(body []byte) error {
	var ops []map[string]json.RawMessage
	if err := json.Unmarshal(body, &ops); err != nil {
		return fmt.Errorf("it is not a JSON patch: %v", err)
	}
	for _, op := range ops {
		var name, path, from string
		if raw, ok := op["op"]; ok {
			_ = json.Unmarshal(raw, &name)
		}
		if raw, ok := op["path"]; ok {
			if err := json.Unmarshal(raw, &path); err != nil {
				return fmt.Errorf("a JSON patch path is not a string")
			}
		}
		if raw, ok := op["from"]; ok {
			_ = json.Unmarshal(raw, &from)
		}
		if s.rules.tokenSecret {
			if err := s.visit("", path); err != nil {
				return err
			}
			if err := s.visit("", from); err != nil {
				return err
			}
		}
		if (s.rules.serviceAccount || s.rules.hostAccess) && (name == "copy" || name == "move") {
			s.deny(DenyWorkloadServiceAccount, fmt.Sprintf(
				"%s %s is refused by the cloop Kubernetes monitor: a JSON patch %q writes a value taken "+
					"from elsewhere in the object, which the monitor cannot check for a ServiceAccount or "+
					"for access to the node. Send the value itself",
				s.req.Verb, s.req.ResourceString(), name))
		}
		if s.denial != nil {
			return nil
		}
		raw, ok := op["value"]
		if !ok {
			continue
		}
		key := lastPointerSegment(path)
		if err := walkJSONUnder(raw, key, s.visit); err != nil {
			return err
		}
		if s.denial != nil {
			return nil
		}
	}
	return nil
}

// lastPointerSegment is the final segment of a JSON pointer, unescaped.
func lastPointerSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
}

// walkJSON visits every key-value pair of one JSON document, duplicates
// included, and fails on anything after it.
func walkJSON(data []byte, visit func(key string, v any) error) error {
	return walkJSONUnder(data, "", visit)
}

// walkJSONUnder is walkJSON for a value that sits under key.
func walkJSONUnder(data []byte, key string, visit func(key string, v any) error) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONValue(dec, key, visit, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("it carries data after its JSON value")
	}
	return nil
}

func walkJSONValue(dec *json.Decoder, key string, visit func(string, any) error, depth int) error {
	if depth > maxInspectDepth {
		return errTooDeep
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("it is not valid JSON: %v", err)
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return visit(key, tok)
	}
	switch delim {
	case '{':
		if err := visit(key, jsonObject{}); err != nil {
			return err
		}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("it is not valid JSON: %v", err)
			}
			k, ok := kt.(string)
			if !ok {
				return errors.New("it is not valid JSON: an object key is not a string")
			}
			if err := walkJSONValue(dec, k, visit, depth+1); err != nil {
				return err
			}
		}
	case '[':
		if err := visit(key, jsonArray{}); err != nil {
			return err
		}
		for dec.More() {
			if err := walkJSONValue(dec, key, visit, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("it is not valid JSON: unexpected %v", delim)
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return fmt.Errorf("it is not valid JSON: %v", err)
	}
	return nil
}

// walkYAML visits every key-value pair of one YAML document. yaml.v3 refuses
// a mapping that repeats a key, resolves merge keys and aliases (and refuses
// a document that aliases excessively), and bounds the nesting it parses.
func walkYAML(data []byte, visit func(key string, v any) error) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("it is not valid YAML: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("it carries more than one YAML document")
	}
	return walkGeneric(doc, "", visit, 0)
}

// walkGeneric visits a decoded YAML value.
func walkGeneric(v any, key string, visit func(string, any) error, depth int) error {
	if depth > maxInspectDepth {
		return errTooDeep
	}
	switch val := v.(type) {
	case map[string]any:
		if err := visit(key, jsonObject{}); err != nil {
			return err
		}
		for k, child := range val {
			if err := walkGeneric(child, k, visit, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[any]any:
		if err := visit(key, jsonObject{}); err != nil {
			return err
		}
		for k, child := range val {
			if err := walkGeneric(child, fmt.Sprint(k), visit, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if err := visit(key, jsonArray{}); err != nil {
			return err
		}
		for _, child := range val {
			if err := walkGeneric(child, key, visit, depth+1); err != nil {
				return err
			}
		}
		return nil
	case nil, string, bool:
		return visit(key, val)
	default:
		// Numbers, timestamps and the rest: none is a name or a flag this
		// file checks, but a ServiceAccount "name" that is one is refused
		// like a number in JSON.
		return visit(key, json.Number(fmt.Sprint(val)))
	}
}
