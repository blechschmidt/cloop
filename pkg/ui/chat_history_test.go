package ui

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestAppendChatMessage_TrimsAtCap verifies the per-workdir chat history
// is bounded — a long-running UI daemon receiving thousands of /api/chat
// posts must not grow its in-memory transcript without limit.
func TestAppendChatMessage_TrimsAtCap(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	const workDir = "/tmp/proj-a"
	for i := 0; i < maxChatHistoryPerWorkDir+50; i++ {
		s.appendChatMessage(workDir, ChatMessage{
			Role:      "user",
			Content:   "msg",
			Timestamp: time.Now(),
		})
	}

	s.chatMu.Lock()
	got := len(s.chatHistories[workDir])
	s.chatMu.Unlock()

	if got != maxChatHistoryPerWorkDir {
		t.Fatalf("history size = %d, want %d (cap)", got, maxChatHistoryPerWorkDir)
	}
}

// TestAppendChatMessage_KeepsMostRecent confirms the trim drops the oldest
// turns, not the newest — losing the latest message would surprise users.
func TestAppendChatMessage_KeepsMostRecent(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	const workDir = "/tmp/proj-b"
	total := maxChatHistoryPerWorkDir + 10
	for i := 0; i < total; i++ {
		s.appendChatMessage(workDir, ChatMessage{
			Role:    "user",
			Content: "m-" + strconv.Itoa(i),
		})
	}

	s.chatMu.Lock()
	hist := append([]ChatMessage(nil), s.chatHistories[workDir]...)
	s.chatMu.Unlock()

	wantLast := "m-" + strconv.Itoa(total-1)
	if hist[len(hist)-1].Content != wantLast {
		t.Fatalf("last message = %q, want %q", hist[len(hist)-1].Content, wantLast)
	}
	wantFirst := "m-" + strconv.Itoa(total-maxChatHistoryPerWorkDir)
	if hist[0].Content != wantFirst {
		t.Fatalf("first kept message = %q, want %q", hist[0].Content, wantFirst)
	}
}

// TestAppendChatMessage_PerWorkDirIsolated ensures one project's history
// trim does not affect another's — the cap is per-workDir.
func TestAppendChatMessage_PerWorkDirIsolated(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	for i := 0; i < maxChatHistoryPerWorkDir+5; i++ {
		s.appendChatMessage("/tmp/proj-c", ChatMessage{Role: "user", Content: "c"})
	}
	for i := 0; i < 3; i++ {
		s.appendChatMessage("/tmp/proj-d", ChatMessage{Role: "user", Content: "d"})
	}

	s.chatMu.Lock()
	gotC := len(s.chatHistories["/tmp/proj-c"])
	gotD := len(s.chatHistories["/tmp/proj-d"])
	s.chatMu.Unlock()

	if gotC != maxChatHistoryPerWorkDir {
		t.Fatalf("proj-c size = %d, want %d", gotC, maxChatHistoryPerWorkDir)
	}
	if gotD != 3 {
		t.Fatalf("proj-d size = %d, want 3 (untrimmed)", gotD)
	}
}

// TestAppendChatMessage_TrimReleasesBackingArray pins that the trim copies
// into a fresh slice with cap == maxChatHistoryPerWorkDir, not a re-slice
// over a huge underlying array. A bare `hist = hist[len(hist)-N:]` would
// keep every dropped message's bytes pinned in memory for the lifetime of
// the daemon, defeating the purpose of the cap.
func TestAppendChatMessage_TrimReleasesBackingArray(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	for i := 0; i < maxChatHistoryPerWorkDir*4; i++ {
		s.appendChatMessage("/proj", ChatMessage{Role: "user", Content: "x"})
	}
	s.chatMu.Lock()
	gotCap := cap(s.chatHistories["/proj"])
	s.chatMu.Unlock()
	if gotCap > maxChatHistoryPerWorkDir {
		t.Fatalf("cap(history) = %d, want <= %d (trim must reallocate)", gotCap, maxChatHistoryPerWorkDir)
	}
}

// TestAppendChatMessage_ConcurrentSafe pounds appendChatMessage from many
// goroutines and confirms the chatMu lock serialises append+trim cleanly —
// no torn slice header, no lost messages beyond the documented cap. Run
// under -race to catch any unprotected map access.
func TestAppendChatMessage_ConcurrentSafe(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	const writers = 8
	const perWriter = 200
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				s.appendChatMessage("/proj", ChatMessage{
					Role:    "user",
					Content: "w" + strconv.Itoa(w) + "-i" + strconv.Itoa(i),
				})
			}
		}(w)
	}
	wg.Wait()

	s.chatMu.Lock()
	got := len(s.chatHistories["/proj"])
	s.chatMu.Unlock()
	if got != maxChatHistoryPerWorkDir {
		t.Fatalf("len(history) = %d, want %d", got, maxChatHistoryPerWorkDir)
	}
}
