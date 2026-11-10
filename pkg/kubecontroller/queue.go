package kubecontroller

// queue.go is the controller's work queue: pool keys waiting to be
// reconciled, each at most once in the queue and never handed to two workers
// at once — a key re-added while it is being reconciled waits until that
// reconcile is done, then runs again. A reconcile that fails is retried with
// a per-key exponential backoff; one that succeeds forgets the count.

import (
	"context"
	"sync"
	"time"
)

// Retry backoff bounds.
var (
	queueBaseDelay = time.Second
	queueMaxDelay  = 5 * time.Minute
)

type workQueue struct {
	mu         sync.Mutex
	order      []string
	queued     map[string]bool
	processing map[string]bool
	// again marks keys re-added while being processed.
	again    map[string]bool
	failures map[string]int
	timers   map[string]*time.Timer
	due      map[string]time.Time
	notify   chan struct{}
	closed   bool
}

func newWorkQueue() *workQueue {
	return &workQueue{queued: map[string]bool{}, processing: map[string]bool{}, again: map[string]bool{},
		failures: map[string]int{}, timers: map[string]*time.Timer{}, due: map[string]time.Time{},
		notify: make(chan struct{}, 1)}
}

// Add queues key now.
func (q *workQueue) Add(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.addLocked(key)
}

func (q *workQueue) addLocked(key string) {
	if q.closed || key == "" {
		return
	}
	if q.processing[key] {
		q.again[key] = true
		return
	}
	if q.queued[key] {
		return
	}
	q.queued[key] = true
	q.order = append(q.order, key)
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// AddAfter queues key after d; a pending AddAfter for it that is due sooner
// wins.
func (q *workQueue) AddAfter(key string, d time.Duration) {
	if d <= 0 {
		q.Add(key)
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	at := time.Now().Add(d)
	if t, ok := q.timers[key]; ok {
		if !q.due[key].After(at) {
			return
		}
		t.Stop()
	}
	q.due[key] = at
	var timer *time.Timer
	timer = time.AfterFunc(d, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.timers[key] == timer {
			delete(q.timers, key)
			delete(q.due, key)
		}
		q.addLocked(key)
	})
	q.timers[key] = timer
}

// AddRateLimited queues key after its backoff, which grows with each call
// until Forget.
func (q *workQueue) AddRateLimited(key string) {
	q.mu.Lock()
	q.failures[key]++
	n := q.failures[key]
	q.mu.Unlock()
	q.AddAfter(key, backoff(n, queueBaseDelay, queueMaxDelay))
}

// Forget clears key's backoff.
func (q *workQueue) Forget(key string) {
	q.mu.Lock()
	delete(q.failures, key)
	q.mu.Unlock()
}

// Get waits for a key, returning false once ctx ends or the queue closes.
func (q *workQueue) Get(ctx context.Context) (string, bool) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return "", false
		}
		if len(q.order) > 0 {
			key := q.order[0]
			q.order = q.order[1:]
			delete(q.queued, key)
			q.processing[key] = true
			if len(q.order) > 0 {
				select {
				case q.notify <- struct{}{}:
				default:
				}
			}
			q.mu.Unlock()
			return key, true
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", false
		case <-q.notify:
		}
	}
}

// Done marks key's reconcile finished, queueing it again if it was re-added
// meanwhile.
func (q *workQueue) Done(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.processing, key)
	if q.again[key] {
		delete(q.again, key)
		q.addLocked(key)
	}
}

// Len is how many keys wait.
func (q *workQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.order)
}

// Close stops the queue and every pending timer.
func (q *workQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	for k, t := range q.timers {
		t.Stop()
		delete(q.timers, k)
		delete(q.due, k)
	}
	select {
	case q.notify <- struct{}{}:
	default:
	}
}
