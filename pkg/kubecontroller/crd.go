package kubecontroller

import _ "embed"

// crdYAML is the ExecutorPool CustomResourceDefinition.
//
//go:embed crds/cloop.dev_executorpools.yaml
var crdYAML []byte

// CRD returns the ExecutorPool CustomResourceDefinition as YAML, for
// `cloop executor controller crd | kubectl apply -f -`.
func CRD() []byte { return append([]byte(nil), crdYAML...) }
