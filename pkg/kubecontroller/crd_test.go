package kubecontroller

// crd_test.go holds the CRD in crds/ and the Go types to the same fields, and
// checks the rules a real API server enforces from the CRD are stated there:
// a field only one side knows is a field one side silently drops.

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type crdSchema struct {
	Type                  string               `yaml:"type"`
	Required              []string             `yaml:"required"`
	Properties            map[string]crdSchema `yaml:"properties"`
	Items                 *crdSchema           `yaml:"items"`
	AdditionalProperties  *crdSchema           `yaml:"additionalProperties"`
	PreserveUnknownFields bool                 `yaml:"x-kubernetes-preserve-unknown-fields"`
	IntOrString           bool                 `yaml:"x-kubernetes-int-or-string"`
	Validations           []map[string]string  `yaml:"x-kubernetes-validations"`
	Default               any                  `yaml:"default"`
	Enum                  []string             `yaml:"enum"`
	Minimum               *int                 `yaml:"minimum"`
	Maximum               *int                 `yaml:"maximum"`
	MaxItems              *int                 `yaml:"maxItems"`
	MaxProperties         *int                 `yaml:"maxProperties"`
	MaxLength             *int                 `yaml:"maxLength"`
	Pattern               string               `yaml:"pattern"`
	ListType              string               `yaml:"x-kubernetes-list-type"`
	ListMapKeys           []string             `yaml:"x-kubernetes-list-map-keys"`
}

type crdDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Group string `yaml:"group"`
		Scope string `yaml:"scope"`
		Names struct {
			Kind   string `yaml:"kind"`
			Plural string `yaml:"plural"`
		} `yaml:"names"`
		Versions []struct {
			Name         string         `yaml:"name"`
			Served       bool           `yaml:"served"`
			Storage      bool           `yaml:"storage"`
			Subresources map[string]any `yaml:"subresources"`
			Schema       struct {
				OpenAPIV3Schema crdSchema `yaml:"openAPIV3Schema"`
			} `yaml:"schema"`
		} `yaml:"versions"`
	} `yaml:"spec"`
}

func loadCRD(t *testing.T) crdDoc {
	t.Helper()
	var d crdDoc
	if err := yaml.Unmarshal(CRD(), &d); err != nil {
		t.Fatalf("the CRD is not YAML: %v", err)
	}
	return d
}

func TestTheCRDNamesTheResource(t *testing.T) {
	d := loadCRD(t)
	if d.APIVersion != "apiextensions.k8s.io/v1" || d.Kind != "CustomResourceDefinition" || d.Metadata.Name != CRDName {
		t.Fatalf("the CRD is %s %s %s", d.APIVersion, d.Kind, d.Metadata.Name)
	}
	if d.Spec.Group != Group || d.Spec.Scope != "Namespaced" || d.Spec.Names.Kind != Kind || d.Spec.Names.Plural != Plural {
		t.Fatalf("the CRD serves %+v", d.Spec)
	}
	if len(d.Spec.Versions) != 1 {
		t.Fatalf("the CRD has %d versions", len(d.Spec.Versions))
	}
	v := d.Spec.Versions[0]
	if v.Name != Version || !v.Served || !v.Storage {
		t.Fatalf("version %+v", v)
	}
	if _, ok := v.Subresources["status"]; !ok {
		t.Fatal("the CRD has no status subresource: the controller's status writes would rewrite the spec")
	}
}

// jsonFields lists a struct type's JSON field names.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

// sameFields walks a Go struct and a schema side by side.
func sameFields(t *testing.T, path string, typ reflect.Type, s crdSchema) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		if s.PreserveUnknownFields && len(s.Properties) == 0 {
			return
		}
		goFields := jsonFields(typ)
		var goNames, crdNames []string
		for n := range goFields {
			goNames = append(goNames, n)
		}
		for n := range s.Properties {
			crdNames = append(crdNames, n)
		}
		sort.Strings(goNames)
		sort.Strings(crdNames)
		if !reflect.DeepEqual(goNames, crdNames) {
			t.Errorf("%s: Go has %v, the CRD has %v", path, goNames, crdNames)
			return
		}
		for n, ft := range goFields {
			sameFields(t, path+"."+n, ft, s.Properties[n])
		}
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 { // json.RawMessage
			return
		}
		if s.Items == nil {
			t.Errorf("%s: a list in Go, no items in the CRD", path)
			return
		}
		sameFields(t, path+"[]", typ.Elem(), *s.Items)
	case reflect.Map:
		if s.AdditionalProperties == nil {
			t.Errorf("%s: a map in Go, no additionalProperties in the CRD", path)
		}
	}
}

func TestTheCRDAndTheGoTypesHaveTheSameFields(t *testing.T) {
	d := loadCRD(t)
	root := d.Spec.Versions[0].Schema.OpenAPIV3Schema
	sameFields(t, "spec", reflect.TypeOf(ExecutorPoolSpec{}), root.Properties["spec"])
	sameFields(t, "status", reflect.TypeOf(ExecutorPoolStatus{}), root.Properties["status"])
	// The affinity is passed through, and its three keys are declared.
	aff := root.Properties["spec"].Properties["template"].Properties["affinity"]
	for _, k := range []string{"nodeAffinity", "podAffinity", "podAntiAffinity"} {
		if !aff.Properties[k].PreserveUnknownFields {
			t.Errorf("affinity.%s does not preserve its fields", k)
		}
	}
}

// The rules the Go validation repeats are stated in the CRD too.
func TestTheCRDStatesTheRulesValidateRepeats(t *testing.T) {
	d := loadCRD(t)
	spec := d.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
	req := map[string]bool{}
	for _, r := range spec.Required {
		req[r] = true
	}
	for _, f := range []string{"hubURL", "poolCredentialSecretRef", "maxRunners"} {
		if !req[f] {
			t.Errorf("spec.%s is not required in the CRD", f)
		}
	}
	rules := func(s crdSchema) string {
		var b strings.Builder
		for _, v := range s.Validations {
			b.WriteString(v["rule"] + "\n")
		}
		return b.String()
	}
	for _, want := range []struct{ where, rule string }{
		{"spec", "self.minRunners <= self.maxRunners"},
		{"spec", "e.secretKeyRef.name != self.poolCredentialSecretRef.name"},
		{"hubURL", "url(self).getScheme() == 'https'"},
		{"scaleDownDelay", "duration(self) <= duration('24h')"},
		{"runnerLabels", "!k.startsWith('cloop.dev/')"},
		{"hubCABundle", "BEGIN CERTIFICATE"},
		{"template", "self.serviceAccountName != 'default'"},
	} {
		s := spec
		if want.where != "spec" {
			s = spec.Properties[want.where]
		}
		if !strings.Contains(rules(s), want.rule) {
			t.Errorf("the CRD's %s has no rule %q", want.where, want.rule)
		}
	}
	if m := spec.Properties["maxRunners"]; m.Maximum == nil || *m.Maximum != 1000 {
		t.Errorf("maxRunners' maximum is not the hub's ceiling of 1000")
	}
	if d := spec.Properties["scaleDownDelay"].Default; d != DefaultScaleDownDelay {
		t.Errorf("scaleDownDelay defaults to %v", d)
	}
	if d := spec.Properties["poolCredentialSecretRef"].Properties["key"].Default; d != DefaultCredentialKey {
		t.Errorf("the credential key defaults to %v", d)
	}
	env := spec.Properties["template"].Properties["env"]
	if env.ListType != "map" || len(env.ListMapKeys) != 1 || env.ListMapKeys[0] != "name" {
		t.Errorf("template.env is not a map list keyed by name: %+v", env)
	}
	if !strings.Contains(rules(*env.Items), "startsWith('CLOOP_')") {
		t.Error("template.env does not refuse the CLOOP_ variables")
	}
	// Every collection a CEL rule iterates is bounded, or a real API server
	// refuses the CRD for its estimated cost.
	for _, p := range []string{"runnerLabels"} {
		if spec.Properties[p].MaxProperties == nil {
			t.Errorf("spec.%s has CEL rules and no maxProperties", p)
		}
	}
}
