// Package taskfill builds a pm.Task with every exported field set, for tests
// that must notice when a store drops one (Task 20361).
//
// statedb enumerated plan_tasks' columns by hand, and fourteen pm.Task fields
// were never among them: an assignee, a sprint, a plan's on_success branches
// all read back as zero after the next load. Nothing noticed, because every
// test that checked persistence named the fields it set — and a field nobody
// knew was missing is the one nobody sets. A test built on Task instead covers
// every field, including the next one somebody adds, and fails until the store
// keeps it or the test is told why it does not.
//
// Values are distinct per field and per task number, so a store that wrote one
// field's value into another's column fails too, not only one that drops it.
package taskfill

import (
	"fmt"
	"reflect"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// base is the earliest timestamp Task produces. It carries nanoseconds so a
// store that keeps only seconds is caught.
var base = time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

var timeType = reflect.TypeOf(time.Time{})

// Task returns a task numbered id whose every other exported field holds a
// non-zero value that no other field shares, recursing into slices, pointers
// and nested structs. Times are in UTC.
//
// It panics on a field kind it does not know how to fill, naming the field:
// that is a new pm.Task field this package has to learn about, and a test that
// silently left it zero would be the gap this package exists to close.
func Task(id int) *pm.Task {
	t := &pm.Task{}
	f := &filler{id: id}
	v := reflect.ValueOf(t).Elem()
	for i := 0; i < v.NumField(); i++ {
		sf := v.Type().Field(i)
		if !sf.IsExported() {
			continue
		}
		f.fill(v.Field(i), sf.Name)
	}
	t.ID = id
	return t
}

type filler struct {
	id int
	n  int // one more for every leaf filled, so values never repeat
}

func (f *filler) fill(v reflect.Value, path string) {
	f.n++
	switch v.Kind() {
	case reflect.String:
		v.SetString(fmt.Sprintf("%s-%d", path, f.id))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(f.id*100 + f.n))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(f.id*100 + f.n))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(f.id) + float64(f.n)/4)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Struct:
		if v.Type() == timeType {
			at := base.Add(time.Duration(f.id)*time.Hour + time.Duration(f.n)*time.Second)
			v.Set(reflect.ValueOf(at))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			sf := v.Type().Field(i)
			if sf.IsExported() {
				f.fill(v.Field(i), path+"."+sf.Name)
			}
		}
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		f.fill(p.Elem(), path)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		f.fill(s.Index(0), path+"[0]")
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMapWithSize(v.Type(), 1)
		k := reflect.New(v.Type().Key()).Elem()
		e := reflect.New(v.Type().Elem()).Elem()
		f.fill(k, path+".key")
		f.fill(e, path+".value")
		m.SetMapIndex(k, e)
		v.Set(m)
	default:
		panic(fmt.Sprintf("taskfill: no value for %s (%s); teach taskfill this kind", path, v.Type()))
	}
}

// Fields returns the names of pm.Task's exported fields, in declaration order.
func Fields() []string {
	ty := reflect.TypeOf(pm.Task{})
	var out []string
	for i := 0; i < ty.NumField(); i++ {
		if sf := ty.Field(i); sf.IsExported() {
			out = append(out, sf.Name)
		}
	}
	return out
}

// Diff returns the exported fields of pm.Task whose values differ between want
// and got, in declaration order, leaving out the fields named in skip.
//
// Values are compared the way a store can faithfully return them: times as
// instants (a database hands back the same moment in another location), and a
// nil slice as equal to an empty one (JSON's null and [] both mean "none").
func Diff(want, got *pm.Task, skip ...string) []string {
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}
	wv, gv := reflect.ValueOf(want).Elem(), reflect.ValueOf(got).Elem()
	var out []string
	for i := 0; i < wv.NumField(); i++ {
		sf := wv.Type().Field(i)
		if !sf.IsExported() || skipped[sf.Name] {
			continue
		}
		if !equal(wv.Field(i), gv.Field(i)) {
			out = append(out, sf.Name)
		}
	}
	return out
}

func equal(a, b reflect.Value) bool {
	if a.Type() == timeType {
		return a.Interface().(time.Time).Equal(b.Interface().(time.Time))
	}
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return equal(a.Elem(), b.Elem())
	case reflect.Slice:
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !equal(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if a.Type().Field(i).IsExported() && !equal(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		for _, k := range a.MapKeys() {
			bv := b.MapIndex(k)
			if !bv.IsValid() || !equal(a.MapIndex(k), bv) {
				return false
			}
		}
		return true
	}
	return a.Interface() == b.Interface()
}
