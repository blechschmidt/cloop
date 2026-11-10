package cmd

// executor_controller_cmd.go is `cloop executor controller` (Task 20483): the
// in-cluster controller that keeps executor pools' ephemeral runners as Pods.
// It is part of the main binary so the release signing and the edge channel
// that cover every other cloop process cover it too.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/kubecontroller"
)

var executorControllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Run the Kubernetes executor controller that keeps executor pools' runners as Pods",
	Long: `Run the executor controller in a Kubernetes cluster.

The controller watches ExecutorPool objects (cloop.dev/v1alpha1) in its
namespace. For each one it keeps the pool's demand feed on the hub open, starts
runner Pods as runs queue for the pool, and retires idle runners when the
demand falls. Each runner runs ` + "`cloop executor agent --ephemeral`" + ` with a
just-in-time configuration the hub minted for it, kept in a Secret the Pod owns:
it enrolls, takes one run, and exits, and the controller deletes it.

In a Pod it authenticates as its ServiceAccount; elsewhere --kubeconfig names a
cluster. Run more than one replica for availability: a Lease elects the one that
scales. Install the resource first:

    cloop executor controller crd | kubectl apply -f -

and give the ServiceAccount the rules ` + "`cloop executor controller rbac`" + ` prints.`,
	Args: cobra.NoArgs,
	RunE: runExecutorController,
}

var executorControllerCRDCmd = &cobra.Command{
	Use:   "crd",
	Short: "Print the ExecutorPool CustomResourceDefinition",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := cmd.OutOrStdout().Write(kubecontroller.CRD())
		return err
	},
}

var executorControllerRBACCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Print the Role rules the controller's ServiceAccount needs",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Fprint(cmd.OutOrStdout(), kubecontroller.RulesYAML())
		return err
	},
}

func runExecutorController(cmd *cobra.Command, _ []string) error {
	namespace, _ := cmd.Flags().GetString("namespace")
	allNamespaces, _ := cmd.Flags().GetBool("all-namespaces")
	kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
	kubeContext, _ := cmd.Flags().GetString("context")
	leaderElect, _ := cmd.Flags().GetBool("leader-elect")
	leNamespace, _ := cmd.Flags().GetString("leader-election-namespace")
	leName, _ := cmd.Flags().GetString("leader-election-name")
	resync, _ := cmd.Flags().GetDuration("resync")
	workers, _ := cmd.Flags().GetInt("workers")
	healthAddr, _ := cmd.Flags().GetString("health-addr")
	provenance, _ := cmd.Flags().GetString("image-provenance")
	requireDigest, _ := cmd.Flags().GetBool("require-image-digest")

	required := false
	switch strings.ToLower(strings.TrimSpace(provenance)) {
	case "", "warn":
	case "required":
		required = true
	default:
		return fmt.Errorf("--image-provenance must be warn or required, not %q", provenance)
	}
	if resync < 30*time.Second {
		return fmt.Errorf("--resync must be at least 30s")
	}

	rest, token, homeNamespace, err := controllerAPIConfig(kubeconfig, kubeContext)
	if err != nil {
		return err
	}
	// The account the controller runs as, so no pool's runners run as it
	// (Task 20485): read from the token it authenticates with, which in a Pod
	// is its ServiceAccount's.
	var self *kubecontroller.ServiceAccountRef
	tok := rest.BearerToken
	if token != nil {
		if t, err := token(); err == nil {
			tok = t
		}
	}
	if sa, ok := kubecontroller.ServiceAccountFromToken(tok); ok {
		self = &sa
	}
	if allNamespaces {
		namespace = ""
	} else if strings.TrimSpace(namespace) == "" {
		namespace = homeNamespace
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "%s [executor-controller] %s\n", time.Now().UTC().Format(time.RFC3339),
			fmt.Sprintf(format, args...))
	}
	opts := kubecontroller.Options{REST: rest, Token: token, Namespace: namespace, Resync: resync, Workers: workers,
		HealthAddr: healthAddr, ImageProvenanceRequired: required, RequireImageDigest: requireDigest,
		ServiceAccount: self, Logf: logf}
	if leaderElect {
		if strings.TrimSpace(leNamespace) == "" {
			leNamespace = homeNamespace
		}
		opts.LeaderElection = &kubecontroller.LeaderElection{Namespace: leNamespace, Name: leName,
			Identity: controllerIdentity()}
	}
	c, err := kubecontroller.New(opts)
	if err != nil {
		return err
	}
	scope := "namespace " + namespace
	if namespace == "" {
		scope = "every namespace"
	}
	logf("watching ExecutorPools in %s on %s", scope, rest.Server)
	if opts.LeaderElection != nil {
		logf("leader election: Lease %s/%s as %s", leNamespace, leName, opts.LeaderElection.Identity)
	} else {
		logf("leader election is off: run exactly one replica")
	}
	if self != nil {
		logf("runs as ServiceAccount %s, which no runner may run as", self)
	}
	if requireDigest {
		logf("runner images must be pinned by digest")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.Run(ctx); err != nil {
		return err
	}
	logf("stopped")
	return nil
}

// controllerAPIConfig reaches the API server: the Pod's ServiceAccount, or a
// kubeconfig when one is named. It returns the namespace the controller lives
// in, for the defaults.
func controllerAPIConfig(kubeconfig, kubeContext string) (*kubernetes.RESTConfig, func() (string, error), string, error) {
	if path := strings.TrimSpace(kubeconfig); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, "", fmt.Errorf("read --kubeconfig: %w", err)
		}
		rc, err := kubernetes.ParseKubeconfig(raw, kubeContext)
		if err != nil {
			return nil, nil, "", err
		}
		ns := rc.Namespace
		if ns == "" {
			ns = "default"
		}
		return rc, nil, ns, nil
	}
	src, err := kubernetes.NewInClusterSource("")
	if err != nil {
		if errors.Is(err, kubernetes.ErrNotInCluster) {
			return nil, nil, "", fmt.Errorf("%w\nOutside a cluster, name one with --kubeconfig", err)
		}
		return nil, nil, "", err
	}
	creds, err := src.Acquire(context.Background(), "")
	if err != nil {
		return nil, nil, "", err
	}
	// The projected token is re-read as the kubelet rotates it, at most once a
	// minute.
	var mu sync.Mutex
	tok, readAt := creds.Rest.BearerToken, time.Now()
	token := func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if tok != "" && time.Since(readAt) < time.Minute {
			return tok, nil
		}
		fresh, err := src.Renew(context.Background(), "")
		if err != nil {
			if tok != "" {
				return tok, nil
			}
			return "", err
		}
		tok, readAt = fresh.Rest.BearerToken, time.Now()
		return tok, nil
	}
	return creds.Rest, token, creds.Namespace, nil
}

// controllerIdentity is this replica's leader-election identity: its Pod's
// name, and a random suffix so a restarted Pod is a new holder.
func controllerIdentity() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "cloop-executor-controller"
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return host + "_" + hex.EncodeToString(b)
}

func init() {
	f := executorControllerCmd.Flags()
	f.String("namespace", "", "namespace whose ExecutorPools the controller serves (default: its own)")
	f.Bool("all-namespaces", false, "serve ExecutorPools in every namespace (needs a ClusterRole)")
	f.String("kubeconfig", "", "kubeconfig to reach the cluster with, outside a Pod (default: the Pod's ServiceAccount)")
	f.String("context", "", "kubeconfig context (default: its current-context)")
	f.Bool("leader-elect", true, "hold a Lease so only one replica scales; turn off only with exactly one replica")
	f.String("leader-election-namespace", "", "namespace of the leader-election Lease (default: the controller's own)")
	f.String("leader-election-name", "cloop-executor-controller", "name of the leader-election Lease")
	f.Duration("resync", 5*time.Minute, "relist everything and reconcile every pool this often")
	f.Int("workers", 2, "pools reconciled at once")
	f.String("health-addr", ":8081", "serve /healthz and /readyz on this address (\"\" for none)")
	f.String("image-provenance", "warn",
		"warn or required: whether a runner image of cloop's own whose signature cannot be verified still runs")
	f.Bool("require-image-digest", false,
		"refuse a pool whose template names its runner image by tag rather than repository@sha256:…")

	executorControllerCmd.AddCommand(executorControllerCRDCmd)
	executorControllerCmd.AddCommand(executorControllerRBACCmd)
	executorCmd.AddCommand(executorControllerCmd)
}
