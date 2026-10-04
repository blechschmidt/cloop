// Command egressfetch fetches one URL the way a harness that honours
// HTTPS_PROXY does, and reports what happened on one line. The egress e2e
// (egress_container_test.go) runs it inside a sandbox whose only way out is
// the hub's egress proxy.
//
//	egressfetch -ca /workspace/ca.pem https://172.17.0.1:43210/allowed
//	status=200 body="the origin answered"
//	error="Get \"https://10.1.0.4:43210/denied\": Forbidden"
//
// It lives under testdata so `go build ./...` and the orphan check never see
// it; the test builds it, statically, for the sandbox image.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	ca := flag.String("ca", "", "PEM file of the CA the origin's certificate chains to")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Println(`error="usage: egressfetch -ca ca.pem URL"`)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			fmt.Printf("error=%q\n", fmt.Sprintf("read CA %s: %v", *ca, err))
			os.Exit(2)
		}
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Get(flag.Arg(0))
	if err != nil {
		fmt.Printf("error=%q\n", err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("status=%d body=%q\n", resp.StatusCode, strings.TrimSpace(string(body)))
}
