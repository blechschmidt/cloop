// Command forge serves pkg/secretbroker/secretbrokertest's git forge over TLS,
// for the Kubernetes end-to-end test (tests/kube, Task 20385).
//
// In the kind cluster it is github.com: the hub reaches it under that name
// through a hostAliases entry and trusts the test CA that signed its
// certificate, so a guarded GitHub lease and a git workspace both take their
// production paths through the git proxy and arrive here. It honours exactly
// one credential — the PAT the test stored in the hub — and honours it for
// every repository it serves, so a refusal of the second repository can only
// have come from the proxy.
//
// It is a test fixture, not a forge: no TLS options, no access log beyond the
// counts on stderr, and the PAT is read from a file (a mounted Secret) so it
// appears in neither the Pod spec nor the process table.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "forge: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8443", "address to serve HTTPS on")
	certFile := flag.String("cert", "/tls/tls.crt", "server certificate (PEM)")
	keyFile := flag.String("key", "/tls/tls.key", "server key (PEM)")
	root := flag.String("root", "/srv/git", "where the bare repositories live")
	home := flag.String("home", "/srv/home", "HOME for the forge's own git commands")
	repos := flag.String("repos", "", "comma-separated owner/name repositories to seed")
	patFile := flag.String("pat-file", "/pat/token", "file holding the one PAT the forge honours")
	flag.Parse()

	raw, err := os.ReadFile(*patFile)
	if err != nil {
		return fmt.Errorf("read the PAT: %w", err)
	}
	pat := strings.TrimSpace(string(raw))
	if pat == "" {
		return errors.New("the PAT file is empty")
	}
	gh := secretbrokertest.NewGitHub()
	gh.AcceptPAT(pat) // every repository: the proxy is what narrows it

	var names []string
	for _, r := range strings.Split(*repos, ",") {
		if r = strings.TrimSpace(r); r != "" {
			names = append(names, r)
		}
	}
	if len(names) == 0 {
		return errors.New("--repos names no repository")
	}
	forge, err := secretbrokertest.NewForgeHandler(secretbrokertest.ForgeConfig{
		GitHub: gh, Root: *root, Home: *home, Repos: names,
	})
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return fmt.Errorf("load the TLS pair: %w", err)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           forge,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	fmt.Fprintf(os.Stderr, "forge: serving %s on %s\n", strings.Join(names, ", "), *listen)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted, refused := forge.Counts()
	fmt.Fprintf(os.Stderr, "forge: shutting down; admitted %d requests, refused %d\n", accepted, refused)
	return srv.Shutdown(shutdown)
}
