package scim

// PATCH (RFC 7644 §3.5.2), in the dialects the providers speak.
//
// Three readings differ from the letter of the RFC, each because a provider
// means something the RFC would do differently:
//
//   - A remove whose path is a multi-valued attribute and which carries a
//     value removes the values given, not the whole attribute. That is Entra
//     ID's member removal — {"op":"Remove","path":"members","value":[{"value":
//     "<id>"}]} — and read literally it would empty the group.
//   - An add or replace whose value path matches no element creates one, with
//     the filter's equalities as its attributes: Entra replaces
//     emails[type eq "work"].value on a user who has no work address, and
//     means "set it".
//   - A remove whose value path matches nothing succeeds. Removing what is not
//     there is the state asked for, and a retried removal — or one reordered
//     after a delete — must not fail the provisioning cycle.
//
// A path-less operation's value is an object whose keys may themselves be
// paths ("name.givenName", `emails[type eq "work"].value`): that is how Entra
// sends attribute updates with its SCIM 2.0 compliance flag on.

import (
	"encoding/json"
	"reflect"
	"strings"
)

// maxPatchOps bounds a PATCH request.
const maxPatchOps = 1000

// PatchOp is one PATCH operation.
type PatchOp struct {
	// Op is add, replace or remove, lowercased.
	Op string
	// Path is the target, or "" for a path-less operation.
	Path string
	// Value is the operation's value; HasValue says whether one was given.
	Value    any
	HasValue bool
}

// ParsePatch parses a PATCH request body. Member names are matched
// case-insensitively ("Operations", "operations"), and so is the op.
func ParsePatch(body []byte) ([]PatchOp, error) {
	obj, err := Decode(body)
	if err != nil {
		return nil, err
	}
	raw, ok := lookup(obj, "Operations")
	if !ok {
		return nil, BadRequest(ErrInvalidSyntax, "a PATCH request carries an Operations list")
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, BadRequest(ErrInvalidSyntax, "Operations must be a list")
	}
	if len(list) == 0 {
		return nil, BadRequest(ErrInvalidSyntax, "Operations is empty")
	}
	if len(list) > maxPatchOps {
		return nil, Errorf(413, ErrTooMany, "a PATCH request carries %d operations; the limit is %d",
			len(list), maxPatchOps)
	}
	ops := make([]PatchOp, 0, len(list))
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, BadRequest(ErrInvalidSyntax, "operation %d is not an object", i)
		}
		var op PatchOp
		if v, ok := lookup(m, "op"); ok {
			s, _ := v.(string)
			op.Op = strings.ToLower(strings.TrimSpace(s))
		}
		switch op.Op {
		case "add", "replace", "remove":
		default:
			return nil, BadRequest(ErrInvalidSyntax, "operation %d: op %s is not add, replace or remove",
				i, Describe(m["op"]))
		}
		if v, ok := lookup(m, "path"); ok && v != nil {
			s, isString := v.(string)
			if !isString {
				return nil, BadRequest(ErrInvalidPath, "operation %d: path must be a string", i)
			}
			op.Path = strings.TrimSpace(s)
		}
		if v, ok := lookup(m, "value"); ok {
			op.Value, op.HasValue = v, true
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// patchPath is a parsed PATCH path: attrPath, or valuePath [subAttr].
type patchPath struct {
	attr   AttrPath
	filter node
	sub    string
	raw    string
}

// parsePatchPath parses PATH = attrPath / valuePath [subAttr].
func parsePatchPath(s string, kind Kind) (patchPath, error) {
	p := patchPath{raw: s}
	open := strings.IndexByte(s, '[')
	if open < 0 {
		ap, err := ParseAttrPath(s, kind)
		if err != nil {
			return p, err
		}
		p.attr = ap
		return p, nil
	}
	close := strings.LastIndexByte(s, ']')
	if close < open {
		return p, BadRequest(ErrInvalidPath, "the path %q opens a filter it does not close", s)
	}
	ap, err := ParseAttrPath(s[:open], kind)
	if err != nil {
		return p, err
	}
	if ap.Sub != "" {
		return p, BadRequest(ErrInvalidPath, "the path %q filters a sub-attribute", s)
	}
	p.attr = ap
	toks, err := tokenize(s[open+1 : close])
	if err != nil {
		return p, err
	}
	pr := &parser{toks: toks, kind: kind}
	n, err := pr.parseOr(0)
	if err != nil {
		return p, err
	}
	if !pr.done() {
		return p, BadRequest(ErrInvalidPath, "the path %q has %q after its filter", s, pr.peek().text)
	}
	p.filter = n
	if rest := s[close+1:]; rest != "" {
		if !strings.HasPrefix(rest, ".") || !validAttrName(rest[1:]) {
			return p, BadRequest(ErrInvalidPath, "the path %q has %q after its filter", s, rest)
		}
		p.sub = rest[1:]
	}
	return p, nil
}

// ApplyPatch applies ops to obj, a normalised resource of kind whose id is id,
// in place. For a group, obj carries its members as {"value": id} entries and
// the caller reads them back with MemberIDs.
func ApplyPatch(obj map[string]any, kind Kind, id string, ops []PatchOp) error {
	for i, op := range ops {
		if err := applyOp(obj, kind, id, op); err != nil {
			if se, ok := err.(*Error); ok {
				se.Detail = "operation " + itoa(i) + " (" + op.Op + pathLabel(op.Path) + "): " + se.Detail
				return se
			}
			return err
		}
	}
	return nil
}

func pathLabel(p string) string {
	if p == "" {
		return ""
	}
	return " " + p
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func applyOp(obj map[string]any, kind Kind, id string, op PatchOp) error {
	if op.Path == "" {
		if op.Op == "remove" {
			return BadRequest(ErrNoTarget, "a remove needs a path")
		}
		vals, ok := op.Value.(map[string]any)
		if !ok {
			return BadRequest(ErrInvalidValue, "an operation without a path takes an object of attributes")
		}
		for k, v := range vals {
			switch strings.ToLower(k) {
			case "schemas", "meta":
				continue
			case "id":
				// Okta repeats the group's id in a rename. The same id is no
				// change; another one is an attempt to change it.
				if s, _ := v.(string); s == id {
					continue
				}
				return Errorf(400, ErrMutability, "id is assigned by the hub and cannot be changed")
			}
			if urn, known := kind.knownURN(k); known && urn != kind.coreSchema().ID {
				// A whole extension object: each of its attributes. A key
				// that is a URN-qualified attribute path — Entra's
				// "urn:…:User:department" — is not a schema id, and is read
				// as the path it is below.
				inner, isObj := v.(map[string]any)
				if !isObj {
					return BadRequest(ErrInvalidValue, "the extension %s takes an object", urn)
				}
				for ik, iv := range inner {
					p, err := parsePatchPath(urn+":"+ik, kind)
					if err != nil {
						return err
					}
					if err := applyPath(obj, kind, op.Op, p, iv, true); err != nil {
						return err
					}
				}
				continue
			}
			p, err := parsePatchPath(k, kind)
			if err != nil {
				return err
			}
			if err := applyPath(obj, kind, op.Op, p, v, true); err != nil {
				return err
			}
		}
		return nil
	}
	p, err := parsePatchPath(op.Path, kind)
	if err != nil {
		return err
	}
	if op.Op != "remove" && !op.HasValue {
		return BadRequest(ErrInvalidValue, "%s needs a value", op.Op)
	}
	return applyPath(obj, kind, op.Op, p, op.Value, op.HasValue)
}

// container returns the object a path's attribute lives in: the resource, or
// the extension object its URN names — created when create is set.
func container(obj map[string]any, p AttrPath, create bool) map[string]any {
	if p.URN == "" {
		return obj
	}
	if key, ok := lookupKey(obj, p.URN); ok {
		if m, isObj := obj[key].(map[string]any); isObj {
			return m
		}
		if !create {
			return nil
		}
		m := map[string]any{}
		obj[key] = m
		return m
	}
	if !create {
		return nil
	}
	m := map[string]any{}
	obj[p.URN] = m
	return m
}

// applyPath applies one operation at one path.
func applyPath(obj map[string]any, kind Kind, op string, p patchPath, value any, hasValue bool) error {
	def := p.attr.definition(kind)
	if p.attr.URN == "" {
		switch strings.ToLower(p.attr.Name) {
		case "id", "meta", "schemas":
			return Errorf(400, ErrMutability, "%s is assigned by the hub and cannot be changed", p.attr.Name)
		case "password":
			if kind == KindUser {
				// Accepted and discarded, as on create: the hub keeps no
				// password, and a provider rotating one must not fail.
				return nil
			}
		case "groups":
			if kind == KindUser {
				return Errorf(400, ErrMutability, "a user's groups follow from the groups' members; "+
					"change the group instead")
			}
		}
	}
	if def != nil && def.Mutability == "readOnly" {
		return Errorf(400, ErrMutability, "%s is read-only", p.attr)
	}
	name := p.attr.Name
	if def != nil {
		name = def.Name
	}
	ctr := container(obj, p.attr, op != "remove")
	if ctr == nil {
		return nil // removing from an extension that is not there
	}
	key, exists := lookupKey(ctr, name)
	if !exists {
		key = name
	}

	// A value path: some elements of a multi-valued attribute.
	if p.filter != nil {
		return applyFiltered(ctr, kind, key, def, op, p, value)
	}

	// A sub-attribute of a complex attribute, with no filter.
	if p.attr.Sub != "" {
		return applySub(ctr, key, exists, def, op, p.attr.Sub, value)
	}

	switch op {
	case "remove":
		if !exists {
			return nil
		}
		if hasValue && value != nil && (def == nil || def.MultiValued) {
			if _, isList := ctr[key].([]any); isList {
				ctr[key] = removeValues(ctr[key].([]any), asList(value))
				return nil
			}
		}
		delete(ctr, key)
		return nil
	case "add", "replace":
		var nv any
		if def != nil {
			var err error
			if nv, err = normalizeValue(def, value); err != nil {
				return err
			}
		} else {
			nv = value
		}
		if def != nil && def.MultiValued {
			if op == "add" {
				ctr[key] = appendValues(asList(ctr[key]), asList(nv))
			} else {
				ctr[key] = asList(nv)
				if nv == nil {
					delete(ctr, key)
				}
			}
			return nil
		}
		if def != nil && def.Type == "complex" {
			// Sub-attributes given replace their values; the others stay
			// (RFC 7644 §3.5.2.1 and .3).
			in, _ := nv.(map[string]any)
			cur, _ := ctr[key].(map[string]any)
			if cur == nil || nv == nil {
				if nv == nil {
					delete(ctr, key)
				} else {
					ctr[key] = in
				}
				return nil
			}
			for k, v := range in {
				if ek, ok := lookupKey(cur, k); ok {
					delete(cur, ek)
				}
				cur[k] = v
			}
			return nil
		}
		if nv == nil {
			delete(ctr, key)
			return nil
		}
		ctr[key] = nv
	}
	return nil
}

// applySub sets or removes one sub-attribute: of a complex attribute, or of
// every element of a multi-valued one.
func applySub(ctr map[string]any, key string, exists bool, def *Attribute, op string, sub string, value any) error {
	var sdef *Attribute
	if def != nil {
		if sdef = def.sub(sub); sdef != nil {
			sub = sdef.Name
		}
	}
	if sdef != nil && op != "remove" && value != nil {
		nv, err := normalizeSingle(sdef, value)
		if err != nil {
			return err
		}
		value = nv
	}
	switch cur := ctr[key].(type) {
	case []any:
		for _, e := range cur {
			if m, isObj := e.(map[string]any); isObj {
				setOrRemove(m, sub, op, value)
			}
		}
		return nil
	case map[string]any:
		setOrRemove(cur, sub, op, value)
		return nil
	}
	if op == "remove" || !exists && value == nil {
		return nil
	}
	m := map[string]any{}
	setOrRemove(m, sub, op, value)
	if def != nil && def.MultiValued {
		ctr[key] = []any{m}
	} else {
		ctr[key] = m
	}
	return nil
}

func setOrRemove(m map[string]any, sub, op string, value any) {
	if k, ok := lookupKey(m, sub); ok {
		delete(m, k)
	}
	if op == "remove" || value == nil {
		return
	}
	m[sub] = value
}

// applyFiltered applies an operation to the elements a value path selects.
func applyFiltered(ctr map[string]any, kind Kind, key string, def *Attribute, op string, p patchPath, value any) error {
	if def != nil && !def.MultiValued {
		return BadRequest(ErrInvalidPath, "%s is not multi-valued, so it cannot be filtered", p.attr)
	}
	list := asList(ctr[key])
	var matched []int
	for i, e := range list {
		if m, isObj := e.(map[string]any); isObj && p.filter.match(m, kind, def) {
			matched = append(matched, i)
		}
	}
	if op == "remove" {
		if len(matched) == 0 {
			return nil
		}
		if p.sub == "" {
			drop := map[int]bool{}
			for _, i := range matched {
				drop[i] = true
			}
			kept := make([]any, 0, len(list))
			for i, e := range list {
				if !drop[i] {
					kept = append(kept, e)
				}
			}
			if len(kept) == 0 {
				delete(ctr, key)
			} else {
				ctr[key] = kept
			}
			return nil
		}
		for _, i := range matched {
			setOrRemove(list[i].(map[string]any), p.sub, "remove", nil)
		}
		ctr[key] = list
		return nil
	}

	// add or replace.
	if p.sub != "" {
		sub := p.sub
		if def != nil {
			if sdef := def.sub(sub); sdef != nil {
				sub = sdef.Name
				if value != nil {
					nv, err := normalizeSingle(sdef, value)
					if err != nil {
						return err
					}
					value = nv
				}
			}
		}
		if len(matched) == 0 {
			elem, ok := elementFromFilter(p.filter)
			if !ok {
				return BadRequest(ErrNoTarget, "%s matches no value, and its filter does not say what one "+
					"would be", p.raw)
			}
			elem[sub] = value
			list = append(list, elem)
			ctr[key] = list
			return nil
		}
		for _, i := range matched {
			setOrRemove(list[i].(map[string]any), sub, "replace", value)
		}
		ctr[key] = list
		return nil
	}
	var nv any = value
	if def != nil {
		v, err := normalizeSingle(def, value)
		if err != nil {
			return err
		}
		nv = v
	}
	in, isObj := nv.(map[string]any)
	if !isObj {
		return BadRequest(ErrInvalidValue, "%s takes an object", p.raw)
	}
	if len(matched) == 0 {
		elem, _ := elementFromFilter(p.filter)
		if elem == nil {
			elem = map[string]any{}
		}
		for k, v := range in {
			elem[k] = v
		}
		ctr[key] = append(list, elem)
		return nil
	}
	for _, i := range matched {
		cur := list[i].(map[string]any)
		if op == "replace" {
			list[i] = in
			continue
		}
		for k, v := range in {
			setOrRemove(cur, k, "replace", v)
		}
	}
	ctr[key] = list
	return nil
}

// elementFromFilter builds the element a value path's filter describes, when
// it is a conjunction of equalities on sub-attributes: type eq "work" yields
// {"type": "work"}.
func elementFromFilter(n node) (map[string]any, bool) {
	out := map[string]any{}
	var walk func(n node) bool
	walk = func(n node) bool {
		switch t := n.(type) {
		case *logicalNode:
			return t.and && walk(t.left) && walk(t.right)
		case *compareNode:
			if t.op != "eq" || t.path.URN != "" || t.path.Sub != "" {
				return false
			}
			out[t.path.Name] = t.value
			return true
		}
		return false
	}
	if !walk(n) {
		return nil, false
	}
	return out, true
}

// appendValues adds values to a multi-valued attribute, skipping any already
// there — by value when the elements have one, whole otherwise — so a retried
// add changes nothing.
func appendValues(cur, add []any) []any {
	out := append([]any(nil), cur...)
	for _, v := range add {
		if containsValue(out, v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// removeValues removes the given values, matched the same way.
func removeValues(cur, rm []any) []any {
	out := make([]any, 0, len(cur))
	for _, e := range cur {
		if containsValue(rm, e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func containsValue(list []any, v any) bool {
	vk, vok := valueKey(v)
	for _, e := range list {
		if ek, eok := valueKey(e); vok && eok {
			if ek == vk {
				return true
			}
			continue
		}
		if reflect.DeepEqual(e, v) {
			return true
		}
	}
	return false
}

// valueKey is an element's value sub-attribute, when it has a string one.
func valueKey(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		if raw, ok := lookup(t, "value"); ok {
			if s, isString := raw.(string); isString {
				return s, true
			}
		}
	case string:
		return t, true
	}
	return "", false
}
