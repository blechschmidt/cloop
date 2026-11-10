package kubecontroller

// informer.go keeps an in-memory copy of one kind of object — ExecutorPools,
// runner Pods, runner Secrets — by list and watch, as client-go's reflector
// does: list, then watch from the list's resourceVersion so nothing between
// the two is missed; follow bookmarks so a quiet watch can resume without a
// relist; relist when the server says the resourceVersion is gone (410); and
// relist anyway on the resync period, so a missed event costs one period at
// most. Every change is handed to onChange, which enqueues the pool it
// concerns.
//
// The copy is the controller's only memory, and it is rebuilt from the API
// server at every start: nothing the controller decides depends on state it
// kept anywhere else (the hub is the other source, read from its feed).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// Watch timing.
var (
	// watchTimeout bounds one watch request: the server ends it, and the
	// informer resumes from the last resourceVersion it saw. Jittered so the
	// controller's three watches do not all reconnect in the same second.
	watchTimeout = 5 * time.Minute
	// maxWatchEvent bounds one watch frame. A runner Pod is a few kilobytes;
	// a frame past this is not one this informer can hold.
	maxWatchEvent = 4 << 20
)

// object is what an informer needs to know about an item.
type object interface {
	meta() ObjectMeta
}

func (p *ExecutorPool) meta() ObjectMeta          { return p.Metadata }
func (p *Pod) meta() ObjectMeta                   { return p.Metadata }
func (s *secretMeta) meta() ObjectMeta            { return s.Metadata }
func (c *PersistentVolumeClaim) meta() ObjectMeta { return c.Metadata }

// informer caches one resource.
type informer[T any, PT interface {
	*T
	object
}] struct {
	api       *kubeAPI
	res       resource
	namespace string
	selector  string
	resync    time.Duration
	logf      func(string, ...any)
	// onChange is called with the old and the new object (either nil, for an
	// add or a delete), outside the lock.
	onChange func(old, cur PT)

	mu     sync.RWMutex
	items  map[string]PT
	synced atomic.Bool
}

func newInformer[T any, PT interface {
	*T
	object
}](api *kubeAPI, res resource, namespace, selector string, resync time.Duration, logf func(string, ...any),
	onChange func(old, cur PT)) *informer[T, PT] {
	return &informer[T, PT]{api: api, res: res, namespace: namespace, selector: selector, resync: resync,
		logf: logf, onChange: onChange, items: map[string]PT{}}
}

// HasSynced reports whether the first list has landed.
func (i *informer[T, PT]) HasSynced() bool { return i.synced.Load() }

// get returns the cached object namespace/name.
func (i *informer[T, PT]) get(key string) (PT, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	o, ok := i.items[key]
	return o, ok
}

// list returns every cached object, in key order.
func (i *informer[T, PT]) list() []PT {
	i.mu.RLock()
	defer i.mu.RUnlock()
	keys := make([]string, 0, len(i.items))
	for k := range i.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]PT, 0, len(keys))
	for _, k := range keys {
		out = append(out, i.items[k])
	}
	return out
}

func metaKey(m ObjectMeta) string { return m.Namespace + "/" + m.Name }

// errRelist ends a watch so the informer lists again at once.
var errRelist = errors.New("kubecontroller: relist")

// run keeps the cache until ctx ends, backing off after failures.
func (i *informer[T, PT]) run(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		err := i.listAndWatch(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil || errors.Is(err, errRelist) {
			failures = 0
			continue
		}
		failures++
		delay := backoff(failures, time.Second, 30*time.Second)
		i.logf("watch %s: %v; listing again in %s", i.res.name, err, delay.Round(time.Millisecond))
		if !sleep(ctx, delay) {
			return
		}
	}
}

// listAndWatch lists, then watches until the resync period, a 410 or a
// failure.
func (i *informer[T, PT]) listAndWatch(ctx context.Context) error {
	raw, rv, err := i.api.list(ctx, i.res, i.namespace, i.selector)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	fresh := make(map[string]PT, len(raw))
	for _, r := range raw {
		o, err := decodeObject[T, PT](r)
		if err != nil {
			i.logf("list %s: skip an object that does not decode: %v", i.res.name, err)
			continue
		}
		fresh[metaKey(o.meta())] = o
	}
	i.replace(fresh)
	i.synced.Store(true)

	deadline := time.Now().Add(jitter(i.resync))
	for ctx.Err() == nil {
		if time.Now().After(deadline) {
			return errRelist
		}
		timeout := min(jitter(watchTimeout), time.Until(deadline)+time.Second)
		if timeout < time.Second {
			timeout = time.Second
		}
		next, err := i.watchOnce(ctx, rv, timeout)
		if err != nil {
			return err
		}
		rv = next
	}
	return ctx.Err()
}

// watchOnce reads one watch request to its end, returning the last
// resourceVersion seen.
func (i *informer[T, PT]) watchOnce(ctx context.Context, rv string, timeout time.Duration) (string, error) {
	body, err := i.api.watch(ctx, i.res, i.namespace, i.selector, rv, timeout)
	if err != nil {
		if kubernetes.IsGone(err) {
			return rv, errRelist
		}
		return rv, fmt.Errorf("watch: %w", err)
	}
	defer body.Close()
	// Close the body when ctx ends, so a quiet watch cannot outlive it.
	stop := context.AfterFunc(ctx, func() { _ = body.Close() })
	defer stop()

	counted := &frameLimit{r: body, max: int64(maxWatchEvent)}
	dec := json.NewDecoder(bufio.NewReaderSize(counted, 64<<10))
	for {
		var ev watchEvent
		err := dec.Decode(&ev)
		counted.reset()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return rv, nil
			}
			return rv, fmt.Errorf("read watch: %w", err)
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			o, err := decodeObject[T, PT](ev.Object)
			if err != nil {
				i.logf("watch %s: skip an object that does not decode: %v", i.res.name, err)
				continue
			}
			i.upsert(o)
			rv = o.meta().ResourceVersion
		case "DELETED":
			o, err := decodeObject[T, PT](ev.Object)
			if err != nil {
				continue
			}
			i.remove(metaKey(o.meta()))
			rv = o.meta().ResourceVersion
		case "BOOKMARK":
			var b struct {
				Metadata ObjectMeta `json:"metadata"`
			}
			if json.Unmarshal(ev.Object, &b) == nil && b.Metadata.ResourceVersion != "" {
				rv = b.Metadata.ResourceVersion
			}
		case "ERROR":
			var st struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			if st.Code == 410 {
				return rv, errRelist
			}
			return rv, fmt.Errorf("watch error %d: %s", st.Code, st.Message)
		}
	}
}

func decodeObject[T any, PT interface {
	*T
	object
}](raw json.RawMessage) (PT, error) {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	p := PT(&v)
	if p.meta().Name == "" {
		return nil, errors.New("an object without a name")
	}
	return p, nil
}

// replace swaps the cache for a fresh list, telling onChange of every
// difference.
func (i *informer[T, PT]) replace(fresh map[string]PT) {
	i.mu.Lock()
	old := i.items
	i.items = fresh
	i.mu.Unlock()
	if i.onChange == nil {
		return
	}
	for k, cur := range fresh {
		prev := old[k]
		if prev == nil || prev.meta().ResourceVersion != cur.meta().ResourceVersion {
			i.onChange(prev, cur)
		}
	}
	for k, prev := range old {
		if _, ok := fresh[k]; !ok {
			i.onChange(prev, nil)
		}
	}
}

// observe stores what this controller itself just wrote, when the cache
// still holds the version it wrote over — so its next pass does not write
// over a version it already replaced. The watch delivers the same object
// shortly; observe only closes the gap.
func (i *informer[T, PT]) observe(o PT, over string) {
	k := metaKey(o.meta())
	i.mu.Lock()
	defer i.mu.Unlock()
	if cur, ok := i.items[k]; ok && cur.meta().ResourceVersion == over {
		i.items[k] = o
	}
}

func (i *informer[T, PT]) upsert(o PT) {
	k := metaKey(o.meta())
	i.mu.Lock()
	prev := i.items[k]
	i.items[k] = o
	i.mu.Unlock()
	if i.onChange != nil {
		i.onChange(prev, o)
	}
}

func (i *informer[T, PT]) remove(k string) {
	i.mu.Lock()
	prev, ok := i.items[k]
	delete(i.items, k)
	i.mu.Unlock()
	if ok && i.onChange != nil {
		i.onChange(prev, nil)
	}
}

// backoff is an exponential delay from base, capped, with ±20% jitter.
func backoff(attempt int, base, ceiling time.Duration) time.Duration {
	d := base
	for n := 1; n < attempt && d < ceiling; n++ {
		d *= 2
	}
	if d > ceiling {
		d = ceiling
	}
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// jitter returns d stretched by up to 20%, never shorter.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Float64()*0.2*float64(d))
}

// sleep waits for d or ctx, reporting whether the wait ran out (true) rather
// than ctx ending.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// frameLimit fails a read once more than max bytes arrived since the last
// reset, so one watch frame cannot make the decoder buffer without bound.
type frameLimit struct {
	r   io.Reader
	n   int64
	max int64
	mu  sync.Mutex
}

func (f *frameLimit) Read(p []byte) (int, error) {
	f.mu.Lock()
	over := f.n > f.max
	f.mu.Unlock()
	if over {
		return 0, fmt.Errorf("a watch event is past this informer's bound of %d bytes", f.max)
	}
	n, err := f.r.Read(p)
	f.mu.Lock()
	f.n += int64(n)
	f.mu.Unlock()
	return n, err
}

func (f *frameLimit) reset() {
	f.mu.Lock()
	f.n = 0
	f.mu.Unlock()
}
