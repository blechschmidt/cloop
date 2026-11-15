//go:build ignore

// forge serves the bare repositories under -root over HTTPS, through git's
// own smart HTTP backend, with a certificate for 127.0.0.1 that it writes to
// -ca. It is the project's origin for run.sh: the device fetches it through
// the reverse tunnel before each run, trusting the certificate through
// GIT_SSL_CAINFO.
//
//	go build -o forge forge.go && ./forge -listen 127.0.0.1:18498 -root DIR -ca ca.pem
package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18498", "address to serve on")
	root := flag.String("root", "", "directory holding the bare repositories")
	ca := flag.String("ca", "", "file to write the server's certificate to")
	flag.Parse()
	if *root == "" || *ca == "" {
		log.Fatal("-root and -ca are required")
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		log.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(&cgi.Handler{
		Path: gitBin,
		Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + *root, "GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"},
		InheritEnv: []string{"PATH"},
	})
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	srv.Listener.Close()
	srv.Listener = l
	srv.StartTLS()
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(*ca, block, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("forge:", srv.URL)
	select {}
}
