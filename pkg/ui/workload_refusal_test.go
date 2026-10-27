package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// TestExecutorRefusalsAreConflictsNotServerErrors: a run the executor refuses
// on purpose — firewall rules a v14 device cannot install, an agent too old for
// what the dispatch carries — is a 409 naming the refusal, not a 500. On the
// live hub (Task 20371) starting a project whose device rules a v14 agent
// could not install answered 500 with the right sentence and no code.
func TestExecutorRefusalsAreConflictsNotServerErrors(t *testing.T) {
	refusals := []error{
		fmt.Errorf("%w: this run is bounded by device d's firewall, but d's agent speaks protocol v14, "+
			"and the hub needs v15", executor.ErrUnsupported),
		fmt.Errorf("%w: agent a (sgx) speaks protocol v2, and the hub needs v3", remote.ErrWorkspaceUnsupported),
		fmt.Errorf("%w: agent a (sgx) speaks protocol v5, and the hub needs v6", remote.ErrSecretFilesUnsupported),
		fmt.Errorf("%w: agent a (sgx) speaks protocol v9, and the hub needs v10", remote.ErrProjectSeedUnsupported),
		fmt.Errorf("%w: agent a (sgx) speaks protocol v7, and the hub needs v8", remote.ErrSandboxModeUnsupported),
		fmt.Errorf("%w: agent a (sgx) speaks protocol v13, and the hub needs v14", remote.ErrVirtualExecutorUnsupported),
		fmt.Errorf("%w: agent a (sgx) speaks protocol v1, and the hub needs v2", remote.ErrRevocationUnsupported),
		// A device without the project's harness that may not install it
		// (Task 20450): a refusal, not a fault.
		fmt.Errorf("%w: agent a (sgx) runs payloads on the device's own host and reports no \"copilot\" there",
			remote.ErrHarnessUnavailable),
	}
	for _, err := range refusals {
		rec := httptest.NewRecorder()
		jsonWorkloadErr(rec, fmt.Errorf("start workload: %w", err))
		if rec.Code != http.StatusConflict {
			t.Errorf("%v: status = %d, want 409", err, rec.Code)
			continue
		}
		var body map[string]any
		if jerr := json.Unmarshal(rec.Body.Bytes(), &body); jerr != nil {
			t.Fatalf("%v: body is not JSON: %v", err, jerr)
		}
		if body["code"] != "executor_unsupported" {
			t.Errorf("%v: code = %v, want executor_unsupported", err, body["code"])
		}
		if msg, _ := body["error"].(string); msg != "start workload: "+err.Error() {
			t.Errorf("%v: error = %q, want the refusal's own sentence", err, msg)
		}
	}

	// A failure that is not a refusal still reads as one.
	rec := httptest.NewRecorder()
	jsonWorkloadErr(rec, errors.New("dial tcp: connection refused"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("an unexpected failure: status = %d, want 500", rec.Code)
	}
}

// TestAnImageWithoutTheHarnessIsAConflict (Task 20450): the image a run would
// start in says it does not carry the project's harness. A 409 with a code of
// its own and the remedy naming an image that carries it.
func TestAnImageWithoutTheHarnessIsAConflict(t *testing.T) {
	err := imagepolicy.CheckHarness("ghcr.io/blechschmidt/cloop-harness:latest",
		map[string]string{imagepolicy.HarnessesLabel: "claude,cloop,git"}, "copilot",
		executor.HarnessImageRemedy("copilot"))
	rec := httptest.NewRecorder()
	jsonWorkloadErr(rec, fmt.Errorf("start workload: %w", err))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body map[string]any
	if jerr := json.Unmarshal(rec.Body.Bytes(), &body); jerr != nil {
		t.Fatal(jerr)
	}
	if body["code"] != "sandbox_image_lacks_harness" {
		t.Errorf("code = %v, want sandbox_image_lacks_harness", body["code"])
	}
	if r, _ := body["remediation"].(string); !strings.Contains(r, executor.HarnessImageFor("copilot")) {
		t.Errorf("remediation = %q, want it to name an image that carries copilot", r)
	}
}
