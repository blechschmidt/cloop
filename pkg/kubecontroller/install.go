package kubecontroller

// install.go: the commands that install a hub pool's controller from the chart
// in deploy/helm/cloop-executor-controller (Task 20486).
//
// Connecting a cluster should be as easy as joining an edge device: the hub
// hands an administrator one block to paste, with its URL, its pin and the
// pool's credential filled in. The dashboard's pool dialog and `cloop executor
// pool create` both print what InstallPlan.Script renders, so the two cannot
// drift; the plan is validated by building the ExecutorPool it creates and
// asking it what the controller would (ExecutorPoolSpec.Validate), so the
// command never installs a pool that comes up Invalid.
//
// The credential goes into a Secret the release names (pool.credential.
// existingSecret), never into a --set value: a value set on the command line
// is kept in the release's stored manifest, which everyone who can read the
// release's Secrets can read back.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/version"
)

// DefaultInstallNamespace is the namespace an install goes to when the plan
// names none and has no pool name to make one from.
const DefaultInstallNamespace = "cloop-runners"

// ChartArchivePath is where a hub serves this chart, packaged, to `helm
// install` (deploy/helm): the chart of the hub's own build.
const ChartArchivePath = "/charts/cloop-executor-controller.tgz"

// InstallPlan is one pool's controller install.
type InstallPlan struct {
	// Chart is the chart reference helm installs: the hub's chart archive
	// URL, or a path to deploy/helm/cloop-executor-controller.
	Chart string
	// Release is the Helm release; Namespace its namespace, which the
	// commands create and label for the restricted Pod Security profile.
	Release   string
	Namespace string
	// PoolName names the ExecutorPool object: the hub pool's name.
	PoolName string
	// HubURL and HubCAPin are the hub's https base URL and the SPKI pin of
	// its key ("" for none).
	HubURL   string
	HubCAPin string
	// CredentialSecret is the Secret, in Namespace, the credential is kept
	// in; Release + "-pool-credential" when empty.
	CredentialSecret string
	// ImageTag is the controller image's tag.
	ImageTag string
	// MinRunners and MaxRunners are the ExecutorPool's.
	MinRunners int
	MaxRunners int
	// Persistence, when set, gives runners volumes that outlive them.
	Persistence *InstallPersistence
}

// InstallPersistence is the runner volumes a plan asks for.
type InstallPersistence struct {
	// StorageClass is the claims' StorageClass, "" for the cluster's default.
	StorageClass string
	// Size is each claim's request, such as 20Gi.
	Size string
	// ReclaimPolicy is Delete (the default) or Retain.
	ReclaimPolicy string
}

// DefaultPersistenceSize is the claim size a plan asks for when it names none.
const DefaultPersistenceSize = "20Gi"

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	imageTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// NamespaceFor is the namespace a pool's controller is installed in when
// the plan names none: cloop-<pool>, one per pool, because the chart is
// installed once per namespace.
func NamespaceFor(pool string) string {
	pool = strings.TrimSpace(pool)
	if pool == "" {
		return DefaultInstallNamespace
	}
	ns := "cloop-" + pool
	if len(ns) > 63 {
		ns = strings.TrimRight(ns[:63], "-")
	}
	return ns
}

// ReleaseFor is the Helm release a pool's controller is installed as when
// the plan names none: the pool's name, within Helm's 53 characters.
func ReleaseFor(pool string) string {
	pool = strings.TrimSpace(pool)
	if len(pool) > 53 {
		pool = strings.TrimRight(pool[:53], "-")
	}
	return pool
}

// ControllerImageTag is the controller image tag for a hub running build
// hubVersion: the release's own tag for a release, otherwise edge, the image
// CI publishes from main, with a note saying why.
func ControllerImageTag(hubVersion string) (tag, note string) {
	if version.IsRelease(hubVersion) {
		return strings.TrimPrefix(strings.TrimSpace(hubVersion), "v"), ""
	}
	return "edge", fmt.Sprintf("This hub runs %s, which is not a release, so the controller image is edge: the "+
		"newest build of main. Pin it with --set image.digest=sha256:… for a fixed one.", displayHubVersion(hubVersion))
}

func displayHubVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "an unnamed build"
	}
	return "build " + strings.TrimSpace(v)
}

// Normalize fills the defaults.
func (p InstallPlan) Normalize() InstallPlan {
	p.PoolName = strings.TrimSpace(p.PoolName)
	p.Release = strings.TrimSpace(p.Release)
	if p.Release == "" {
		p.Release = ReleaseFor(p.PoolName)
	}
	p.Namespace = strings.TrimSpace(p.Namespace)
	if p.Namespace == "" {
		p.Namespace = NamespaceFor(p.PoolName)
	}
	p.CredentialSecret = strings.TrimSpace(p.CredentialSecret)
	if p.CredentialSecret == "" && p.Release != "" {
		p.CredentialSecret = p.Release + "-pool-credential"
	}
	p.HubURL = strings.TrimRight(strings.TrimSpace(p.HubURL), "/")
	p.HubCAPin = strings.TrimSpace(p.HubCAPin)
	p.ImageTag = strings.TrimSpace(p.ImageTag)
	if p.Persistence != nil {
		v := *p.Persistence
		v.StorageClass = strings.TrimSpace(v.StorageClass)
		v.Size = strings.TrimSpace(v.Size)
		if v.Size == "" {
			v.Size = DefaultPersistenceSize
		}
		v.ReclaimPolicy = strings.TrimSpace(v.ReclaimPolicy)
		if v.ReclaimPolicy == "" {
			v.ReclaimPolicy = ReclaimDelete
		}
		p.Persistence = &v
	}
	return p
}

// Pool is the ExecutorPool spec the plan's chart values create, for
// validation.
func (p InstallPlan) Pool() ExecutorPoolSpec {
	spec := ExecutorPoolSpec{HubURL: p.HubURL, HubCAPin: p.HubCAPin,
		PoolCredentialSecretRef: SecretKeyRef{Name: p.CredentialSecret, Key: DefaultCredentialKey},
		MinRunners:              p.MinRunners, MaxRunners: p.MaxRunners}
	if v := p.Persistence; v != nil {
		spec.Persistence = &Persistence{Enabled: true, StorageClassName: v.StorageClass, Size: Quantity(v.Size),
			ReclaimPolicy: v.ReclaimPolicy}
	}
	return spec.Normalize()
}

// Validate reports why the (normalized) plan cannot be installed, nil when it
// can: the ExecutorPool it creates must be one the controller accepts, and
// the names Helm and kubectl are given must be valid.
func (p InstallPlan) Validate() error {
	var problems []string
	switch {
	case p.Release == "" || len(p.Release) > 53 || !dnsLabel.MatchString(p.Release):
		problems = append(problems, fmt.Sprintf("release %q must be 1-53 lowercase letters, digits and dashes", p.Release))
	}
	if p.Namespace == "" || len(p.Namespace) > 63 || !dnsLabel.MatchString(p.Namespace) {
		problems = append(problems, fmt.Sprintf("namespace %q must be 1-63 lowercase letters, digits and dashes", p.Namespace))
	}
	if p.PoolName == "" || len(p.PoolName) > 63 || !dnsLabel.MatchString(p.PoolName) {
		problems = append(problems, fmt.Sprintf("pool name %q must be 1-63 lowercase letters, digits and dashes", p.PoolName))
	}
	if p.Chart == "" || strings.ContainsAny(p.Chart, " \t\n'\"") {
		problems = append(problems, "the chart reference must be one word")
	}
	if p.ImageTag != "" && !imageTag.MatchString(p.ImageTag) {
		problems = append(problems, fmt.Sprintf("image tag %q is not an image tag", p.ImageTag))
	}
	if v := p.Persistence; v != nil && v.ReclaimPolicy != ReclaimDelete && v.ReclaimPolicy != ReclaimRetain {
		problems = append(problems, fmt.Sprintf("persistence reclaim policy %q is not Delete or Retain", v.ReclaimPolicy))
	}
	problems = append(problems, p.Pool().Validate()...)
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// HelmArgs is the plan's `helm install` arguments after the chart, in order:
// the namespace, then each value.
func (p InstallPlan) HelmArgs() []string {
	args := []string{"-n", p.Namespace}
	str := func(k, v string) { args = append(args, "--set-string", k+"="+helmValue(v)) }
	num := func(k string, v int) { args = append(args, "--set", fmt.Sprintf("%s=%d", k, v)) }
	args = append(args, "--set", "pool.create=true")
	str("pool.name", p.PoolName)
	str("pool.hubURL", p.HubURL)
	if p.HubCAPin != "" {
		str("pool.hubCAPin", p.HubCAPin)
	}
	str("pool.credential.existingSecret", p.CredentialSecret)
	num("pool.maxRunners", p.MaxRunners)
	if p.MinRunners > 0 {
		num("pool.minRunners", p.MinRunners)
	}
	if v := p.Persistence; v != nil {
		args = append(args, "--set", "pool.persistence.enabled=true")
		str("pool.persistence.size", v.Size)
		if v.StorageClass != "" {
			str("pool.persistence.storageClassName", v.StorageClass)
		}
		if v.ReclaimPolicy != "" && v.ReclaimPolicy != ReclaimDelete {
			str("pool.persistence.reclaimPolicy", v.ReclaimPolicy)
		}
	}
	if p.ImageTag != "" {
		str("image.tag", p.ImageTag)
	}
	return args
}

// helmValue escapes what --set reads as structure in a value: a comma ends a
// value and a backslash escapes.
func helmValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`).Replace(v)
}

// Script is the block an administrator pastes: the namespace (created if
// missing, labelled for the restricted Pod Security profile), the Secret
// holding credential, and the release. Every command but the last may be run
// again; the last is `helm install`, not `upgrade --install`, which would
// silently replace an existing release's values.
//
// The objects are applied server-side: a client-side `kubectl apply` keeps
// the whole object in its last-applied-configuration annotation, so the
// credential would sit in the Secret's metadata as well, where `kubectl get
// -o yaml` and anything that reads annotations shows it. The namespace's
// Pod Security label is part of its manifest, so a namespace another manager
// labelled otherwise is refused as a conflict rather than overwritten.
func (p InstallPlan) Script(credential string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kubectl apply --server-side -f - <<'EOF'\napiVersion: v1\nkind: Namespace\nmetadata:\n"+
		"  name: %s\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\nEOF\n", p.Namespace)
	b.WriteString(p.secretCommand(credential))
	fmt.Fprintf(&b, "helm install %s %s", shellQuote(p.Release), shellQuote(p.Chart))
	args := p.HelmArgs()
	for i := 0; i < len(args); i += 2 {
		fmt.Fprintf(&b, " \\\n  %s %s", args[i], shellQuote(args[i+1]))
	}
	b.WriteString("\n")
	return b.String()
}

// RotationScript replaces the credential in the Secret the plan's release
// reads. The controller reads the Secret again within five minutes, and at
// once when the hub refuses the credential it holds.
func (p InstallPlan) RotationScript(credential string) string {
	return p.secretCommand(credential)
}

func (p InstallPlan) secretCommand(credential string) string {
	return fmt.Sprintf("kubectl -n %s create secret generic %s \\\n  --from-literal=%s=%s \\\n"+
		"  --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -\n",
		shellQuote(p.Namespace), shellQuote(p.CredentialSecret), DefaultCredentialKey, shellQuote(credential))
}

// UpgradeCommand moves an installed release to the chart and image tag of the
// plan, keeping every other value.
func (p InstallPlan) UpgradeCommand() string {
	cmd := fmt.Sprintf("helm upgrade %s %s -n %s --reuse-values", shellQuote(p.Release), shellQuote(p.Chart),
		shellQuote(p.Namespace))
	if p.ImageTag != "" {
		cmd += " --set-string image.tag=" + shellQuote(p.ImageTag)
	}
	return cmd + "\n"
}

// shellQuote makes v one word in a POSIX shell, quoting only what needs it so
// the block stays readable.
func shellQuote(v string) string {
	if v != "" && strings.IndexFunc(v, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+", r))
	}) < 0 {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
