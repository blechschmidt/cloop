"""projects.py — the three invented projects the demo is recorded from.

record-fixtures.sh creates each project from START (the files committed
before cloop sees it), gives it its goal and TASKS, and runs it through the
hub. stub-claude.py, which stands in for Claude Code during those runs, looks
the task it is given up in WORK and does what the entry says: writes the files,
commits them, prints the summary, and ends the turn the way the entry says
(done, failed, or out of usage).

Everything here is made up for the demo: the names, the code, the data.
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────── todo-api

TODO_MAIN = '''package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	store := NewStore()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\\n"))
	})
	registerTodoRoutes(mux, store)
	log.Printf("todo-api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
'''

TODO_STORE = '''package main

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// Todo is one item on the list.
type Todo struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Done      bool      `json:"done"`
	CreatedAt time.Time `json:"created_at"`
}

// ErrNotFound is returned for an id the store does not hold.
var ErrNotFound = errors.New("todo not found")

// Store keeps the items in memory, safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	next  int
	items map[int]Todo
}

func NewStore() *Store { return &Store{next: 1, items: map[int]Todo{}} }

func (s *Store) Add(title string) Todo {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := Todo{ID: s.next, Title: title, CreatedAt: time.Now().UTC()}
	s.items[t.ID] = t
	s.next++
	return t
}

func (s *Store) Get(id int) (Todo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.items[id]
	if !ok {
		return Todo{}, ErrNotFound
	}
	return t, nil
}

func (s *Store) List() []Todo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Todo, 0, len(s.items))
	for _, t := range s.items {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) SetDone(id int, done bool) (Todo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.items[id]
	if !ok {
		return Todo{}, ErrNotFound
	}
	t.Done = done
	s.items[id] = t
	return t, nil
}

func (s *Store) Delete(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return ErrNotFound
	}
	delete(s.items, id)
	return nil
}
'''

TODO_HANDLERS = '''package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func registerTodoRoutes(mux *http.ServeMux, s *Store) {
	mux.HandleFunc("GET /todos", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.List())
	})
	mux.HandleFunc("POST /todos", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Title) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a todo needs a title"})
			return
		}
		writeJSON(w, http.StatusCreated, s.Add(strings.TrimSpace(in.Title)))
	})
	mux.HandleFunc("GET /todos/{id}", func(w http.ResponseWriter, r *http.Request) {
		withID(w, r, func(id int) (any, error) { return s.Get(id) })
	})
	mux.HandleFunc("PATCH /todos/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Done bool `json:"done"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send {\\"done\\": true|false}"})
			return
		}
		withID(w, r, func(id int) (any, error) { return s.SetDone(id, in.Done) })
	})
	mux.HandleFunc("DELETE /todos/{id}", func(w http.ResponseWriter, r *http.Request) {
		withID(w, r, func(id int) (any, error) { return nil, s.Delete(id) })
	})
}

func withID(w http.ResponseWriter, r *http.Request, fn func(int) (any, error)) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a number"})
		return
	}
	v, err := fn(id)
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	case v == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, v)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
'''

TODO_TESTS = '''package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServer() http.Handler {
	mux := http.NewServeMux()
	registerTodoRoutes(mux, NewStore())
	return mux
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestCreateListAndComplete(t *testing.T) {
	h := newServer()
	if rec := do(t, h, "POST", "/todos", `{"title":"write the release notes"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	if rec := do(t, h, "PATCH", "/todos/1", `{"done":true}`); !strings.Contains(rec.Body.String(), `"done":true`) {
		t.Fatalf("complete = %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, "GET", "/todos", ""); !strings.Contains(rec.Body.String(), "release notes") {
		t.Fatalf("list = %s", rec.Body)
	}
}

func TestRejectsAnEmptyTitle(t *testing.T) {
	if rec := do(t, newServer(), "POST", "/todos", `{"title":"  "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty title = %d, want 400", rec.Code)
	}
}

func TestUnknownIDIs404(t *testing.T) {
	h := newServer()
	for _, m := range []string{"GET", "DELETE"} {
		if rec := do(t, h, m, "/todos/42", ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s /todos/42 = %d, want 404", m, rec.Code)
		}
	}
}
'''

TODO_README = '''# todo-api

A small REST service for to-do lists, kept in memory.

    go run .                 # listens on :8080, or $ADDR

| Method | Path | Does |
| --- | --- | --- |
| GET | /healthz | `ok` while the service is up |
| GET | /todos | every item, oldest first |
| POST | /todos | adds `{"title": "..."}` |
| GET | /todos/{id} | one item |
| PATCH | /todos/{id} | `{"done": true}` marks it done |
| DELETE | /todos/{id} | removes it |

Errors come back as `{"error": "..."}` with a 4xx status.
'''

TODO_COVERAGE = '''ok  	example.com/todo-api	0.014s	coverage: 86.7% of statements

example.com/todo-api/handlers.go:11:	registerTodoRoutes	100.0%
example.com/todo-api/handlers.go:47:	withID			92.3%
example.com/todo-api/handlers.go:66:	writeJSON		100.0%
example.com/todo-api/main.go:9:		main			0.0%
example.com/todo-api/store.go:28:	NewStore		100.0%
example.com/todo-api/store.go:30:	Add			100.0%
example.com/todo-api/store.go:39:	Get			100.0%
example.com/todo-api/store.go:49:	List			100.0%
example.com/todo-api/store.go:60:	SetDone			87.5%
example.com/todo-api/store.go:73:	Delete			100.0%
total:					(statements)		86.7%
'''

TODO_ENDPOINTS_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" width="420" height="150" viewBox="0 0 420 150" font-family="sans-serif" font-size="13">
  <rect width="420" height="150" fill="#f6f8fa"/>
  <text x="16" y="26" font-weight="bold">todo-api: requests by endpoint (load test, 60 s)</text>
  <rect x="120" y="42" width="260" height="18" fill="#4c78a8"/><text x="16" y="56">GET /todos</text><text x="386" y="56">1,940</text>
  <rect x="120" y="68" width="150" height="18" fill="#4c78a8"/><text x="16" y="82">POST /todos</text><text x="276" y="82">1,120</text>
  <rect x="120" y="94" width="96" height="18" fill="#4c78a8"/><text x="16" y="108">PATCH /todos/{id}</text><text x="222" y="108">716</text>
  <rect x="120" y="120" width="30" height="18" fill="#4c78a8"/><text x="16" y="134">DELETE /todos/{id}</text><text x="156" y="134">224</text>
</svg>
'''

# ─────────────────────────────────────────────────────────────── landing-page

PAGE_START = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tidewater</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <main>
  </main>
</body>
</html>
'''

PAGE_HERO = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tidewater</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <nav><a href="#features">Features</a> <a href="#pricing">Pricing</a></nav>
  <main>
    <section class="hero">
      <h1>Tidewater</h1>
      <p>Tide tables for every harbour on the coast, on your phone, offline.</p>
      <a id="signup" class="button" href="#pricing">Start free</a>
    </section>
  </main>
</body>
</html>
'''

PAGE_SECTIONS = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tidewater</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <nav><a href="#features">Features</a> <a href="#pricing">Pricing</a> <a href="#faq">FAQ</a></nav>
  <main>
    <section class="hero">
      <h1>Tidewater</h1>
      <p>Tide tables for every harbour on the coast, on your phone, offline.</p>
      <a id="signup" class="button" href="#pricing">Start free</a>
    </section>
    <section id="features">
      <h2>Features</h2>
      <ul>
        <li>High and low water for 340 harbours, a year ahead</li>
        <li>Works without a signal once the harbour is saved</li>
        <li>A reminder an hour before the tide turns</li>
      </ul>
    </section>
    <section id="pricing">
      <h2>Pricing</h2>
      <p>Free for one harbour. 3 € a month for all of them.</p>
    </section>
  </main>
</body>
</html>
'''

PAGE_DONE = PAGE_SECTIONS.replace(
    '  <link rel="stylesheet" href="styles.css">\n',
    '  <meta name="description" content="Offline tide tables for 340 harbours, with a reminder before the tide turns.">\n'
    '  <link rel="stylesheet" href="styles.css">\n').replace(
    '    </section>\n  </main>',
    '    </section>\n    <section id="faq">\n      <h2>FAQ</h2>\n'
    '      <p><strong>Where do the tide times come from?</strong> From the national hydrographic office, '
    'updated every Sunday.</p>\n    </section>\n  </main>')

PAGE_STYLES = '''body { margin: 0; font-family: system-ui, sans-serif; color: #10324a; }
nav { display: flex; gap: 1rem; padding: 1rem 2rem; background: #e8f2f8; }
.hero { padding: 4rem 2rem; background: linear-gradient(#e8f2f8, #fff); }
.button { display: inline-block; padding: .6rem 1.2rem; border-radius: 6px; background: #1468a0; color: #fff; text-decoration: none; }
section { padding: 2rem; max-width: 46rem; }
'''

PAGE_LINKS_TEST = '''#!/bin/sh
# Every in-page link (href="#x") must point at an element with id="x".
status=0
for target in $(grep -o 'href="#[^"]*"' index.html | sed 's/href="#//; s/"$//' | sort -u); do
  if ! grep -q "id=\\"$target\\"" index.html; then
    echo "index.html: #$target has no element with that id"
    status=1
  fi
done
exit $status
'''

PAGE_DARK = '''@media (prefers-color-scheme: dark) {
  body { background: #0b1d2a; color: #d6e6f2; }
  nav, .hero { background: #10324a; }
  .button { background: #4aa3df; color: #0b1d2a; }
}
'''

# ───────────────────────────────────────────────────────────────── csv-report

CSV_DATA = '''date,region,product,units,revenue_eur
2026-10-01,North,Kettle,14,532.00
2026-10-01,South,Toaster,9,404.10
2026-10-02,East,Kettle,11,418.00
2026-10-02,West,Blender,6,479.40
2026-10-03,North,Blender,4,319.60
2026-10-03,South,Kettle,17,646.00
2026-10-06,East,Toaster,12,538.80
2026-10-06,West,Kettle,8,304.00
2026-10-07,North,Toaster,10,449.00
2026-10-07,South,Blender,5,399.50
'''

CSV_REPORT_START = '''"""report.py — the weekly sales summary, from the monthly CSV export."""

import sys


def main(path: str) -> None:
    raise SystemExit("not written yet: " + path)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/sales-2026-10.csv")
'''

CSV_REPORT_PARSE = '''"""report.py — the weekly sales summary, from the monthly CSV export."""

import csv
import sys
from dataclasses import dataclass
from decimal import Decimal


@dataclass
class Sale:
    date: str
    region: str
    product: str
    units: int
    revenue: Decimal


def read_sales(path: str) -> list[Sale]:
    """Every row of the export, with numbers parsed. A row with a missing or
    malformed number is reported with its line number and skipped."""
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        for line, row in enumerate(csv.DictReader(fh), start=2):
            try:
                out.append(Sale(row["date"], row["region"], row["product"],
                                int(row["units"]), Decimal(row["revenue_eur"])))
            except (KeyError, ValueError, ArithmeticError) as err:
                print(f"{path}:{line}: skipped: {err}", file=sys.stderr)
    return out


def main(path: str) -> None:
    sales = read_sales(path)
    print(f"{len(sales)} sales read from {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/sales-2026-10.csv")
'''

# ─────────────────────────────────────────────────────────── the three projects

PROJECTS = [
    {
        "name": "todo-api",
        "origin": "https://github.com/acme/todo-api.git",
        "goal": "Build a small Go REST service for to-do lists: create, list, complete and delete items, "
                "with tests and a README that documents every endpoint.",
        "instructions": "Standard library only. Every handler answers JSON, errors as {\"error\": \"...\"}.",
        "start": {"README.md": "# todo-api\n\nA small REST service for to-do lists.\n",
                  "go.mod": "module example.com/todo-api\n\ngo 1.22\n"},
        # title, description, role, priority, minutes estimate, tags
        "tasks": [
            ("Scaffold the HTTP server with a health check",
             "A main package that listens on $ADDR (default :8080) and answers GET /healthz with 200 ok.",
             "backend", 1, 20, ["server"]),
            ("Add an in-memory store for to-do items",
             "A Store with Add, Get, List, SetDone and Delete, safe for concurrent use.",
             "backend", 1, 30, ["store"]),
            ("Implement the /todos CRUD handlers",
             "GET/POST /todos and GET/PATCH/DELETE /todos/{id}, JSON in and out, 400 and 404 as JSON errors.",
             "backend", 2, 45, ["server", "api"]),
            ("Cover the handlers with tests",
             "httptest-based tests for create, list, complete, the empty-title 400 and unknown-id 404; "
             "attach the coverage report.",
             "testing", 2, 30, ["tests"]),
            ("Document the API in the README",
             "A table of every endpoint, how to run the service and what an error looks like.",
             "docs", 3, 15, ["docs"]),
        ],
        # A human review gate after the tests (task 4), approved before the README is written.
        "gate": {"title": "Review the API before the first release", "after": 4},
        "requirements": [
            ("Every error is JSON with a 4xx status", "must",
             "A client never has to parse an HTML error page.",
             [("handlers answer JSON errors", "grep -q 'writeJSON(w, http.StatusNotFound' handlers.go")]),
            ("The README documents every endpoint", "should", "Six routes, six rows in the table.",
             [("every route in the README", "test $(grep -c '^| [A-Z]* | /' README.md) -ge 6")]),
        ],
        # Which requirements each task implements, by task number.
        "links": {3: [1], 5: [2]},
    },
    {
        "name": "landing-page",
        "origin": "https://github.com/acme/tidewater-site.git",
        "goal": "Ship the Tidewater landing page: a hero with a sign-up button, features, pricing and an FAQ, "
                "with no third-party scripts and every in-page link working.",
        "instructions": "Plain HTML and CSS, no build step. Keep the page under 30 KB.",
        "start": {"index.html": PAGE_START, "styles.css": PAGE_STYLES,
                  "tests/links.sh": PAGE_LINKS_TEST},
        "requirements": [
            ("The hero names the product and offers a sign-up button", "must",
             "Visitors see what Tidewater is and can start straight away.",
             [("hero has a sign-up button", "grep -q 'id=\"signup\"' index.html")]),
            ("Every in-page link points at a section that exists", "must",
             "No dead #anchors in the navigation or the buttons.",
             [("in-page links resolve", "sh tests/links.sh")]),
            ("The page loads no third-party scripts", "must",
             "Nothing is fetched from another origin when the page loads.",
             [("no remote scripts", "! grep -Eq '<script[^>]+src=\"https?://' index.html")]),
            ("Search engines get a description of the page", "should",
             "A meta description of at most 160 characters.",
             [("meta description present", "grep -q '<meta name=\"description\"' index.html")]),
        ],
        "tasks": [
            ("Build the hero section", "The product name, one sentence on what it does and a Start free button.",
             "frontend", 1, 25, ["hero"], [1, 3]),
            ("Add the features and pricing sections", "Three features as a list; one paragraph on pricing.",
             "frontend", 2, 30, ["content"], [3]),
            ("Check that every in-page link resolves",
             "Run tests/links.sh and fix the page until it passes.",
             "testing", 2, 15, ["links"], [2]),
            ("Add a meta description and an FAQ", "Describe the page for search engines; answer where the "
             "tide times come from.", "frontend", 3, 20, ["seo"], [4]),
        ],
        "feature": {"slug": "dark-mode", "title": "Dark colour scheme",
                    "task": ("Add a dark colour scheme", "Follow prefers-color-scheme: dark; keep the contrast "
                             "of the button at 4.5:1 or better.")},
    },
    {
        "name": "csv-report",
        "origin": "https://github.com/acme/csv-report.git",
        "goal": "Turn the monthly sales CSV export into a weekly Markdown summary by region, generated every "
                "Monday morning.",
        "instructions": "Python 3.12, standard library only.",
        "start": {"report.py": CSV_REPORT_START, "data/sales-2026-10.csv": CSV_DATA,
                  "README.md": "# csv-report\n\nThe weekly sales summary.\n"},
        "tasks": [
            ("Parse the monthly sales export", "Read data/sales-*.csv into typed rows; report and skip bad rows.",
             "data", 1, 20, ["parsing"]),
            ("Summarise sales by region", "Units and revenue per region and product for the week.",
             "data", 2, 30, ["summary"]),
            ("Write the summary as a Markdown report", "A table per region and the week's top product.",
             "data", 2, 25, ["report"]),
            ("Send the report every Monday at 07:00", "A cron entry and a dry-run flag.",
             "devops", 3, 15, ["schedule"]),
        ],
        "requirements": [
            ("Every row of the export is read or reported", "must",
             "A malformed row is named with its line, never dropped in silence.",
             [("all ten rows read", "python3 report.py data/sales-2026-10.csv | grep -q '^10 sales read'")]),
            ("The report shows revenue per region", "must", "North, South, East and West, in euros.",
             [("regions in the report", "python3 report.py data/sales-2026-10.csv | grep -q '^North'")]),
        ],
        "links": {1: [1], 2: [2]},
    },
]


# What each task's turn does, keyed by (project, title): the files it writes
# (path -> content), the commit message, what the agent says, and how the
# turn ends: "done", "fail-once" (fails the first time it runs, succeeds when
# retried) or "usage-limit" (the account's usage runs out).
WORK = {
    ("todo-api", "Scaffold the HTTP server with a health check"): {
        "files": {"main.go": TODO_MAIN.replace("\tstore := NewStore()\n", "").replace(
            "\tregisterTodoRoutes(mux, store)\n", "")},
        "commit": "Scaffold the HTTP server with GET /healthz",
        "say": "Added main.go: the server listens on $ADDR (default :8080) and GET /healthz answers 200 ok. "
               "`go vet ./...` is clean.",
    },
    ("todo-api", "Add an in-memory store for to-do items"): {
        "files": {"store.go": TODO_STORE},
        "commit": "Add an in-memory, mutex-guarded to-do store",
        "say": "Added store.go with Add, Get, List (sorted by id), SetDone and Delete behind one mutex; "
               "an unknown id returns ErrNotFound.",
    },
    ("todo-api", "Implement the /todos CRUD handlers"): {
        "files": {"handlers.go": TODO_HANDLERS, "main.go": TODO_MAIN},
        "commit": "Serve /todos: list, create, read, complete and delete",
        "say": "handlers.go registers the five /todos routes on the 1.22 ServeMux patterns. Bad input is a "
               "400 and an unknown id a 404, both as {\"error\": ...}.",
    },
    ("todo-api", "Cover the handlers with tests"): {
        "files": {"handlers_test.go": TODO_TESTS},
        "commit": "Test the handlers: create, complete, list, 400 and 404",
        "say": "Three httptest tests pass; coverage is 86.7% (main is the only uncovered function). "
               "The coverage report and a chart of the load test are attached.",
        "attach": {"coverage.txt": TODO_COVERAGE, "requests-by-endpoint.svg": TODO_ENDPOINTS_SVG},
    },
    ("todo-api", "Document the API in the README"): {
        "files": {"README.md": TODO_README},
        "commit": "Document every endpoint in the README",
        "say": "The README now has a table of the six endpoints, how to run the service and the error shape.",
    },
    ("landing-page", "Build the hero section"): {
        "files": {"index.html": PAGE_HERO},
        "commit": "Add the hero with the Start free button",
        "say": "The hero names Tidewater, says what it does in one sentence and has the #signup button. "
               "The page still loads no remote script.",
    },
    ("landing-page", "Add the features and pricing sections"): {
        "files": {"index.html": PAGE_SECTIONS},
        "commit": "Add the features and pricing sections",
        "say": "Added #features (three bullet points) and #pricing; the navigation links to both, and to an "
               "FAQ that does not exist yet.",
    },
    ("landing-page", "Check that every in-page link resolves"): {
        "files": {"index.html": PAGE_DONE.replace(
            '  <meta name="description" content="Offline tide tables for 340 harbours, with a reminder before '
            'the tide turns.">\n', "")},
        "commit": "Add the FAQ section the navigation links to",
        "say": "tests/links.sh passes: the navigation's #faq now has a section.",
        "fail_first": "tests/links.sh failed:\n  index.html: #faq has no element with that id\n"
                      "The navigation links to an FAQ section that was never written. I am not going to "
                      "remove the link without knowing whether the FAQ is wanted.",
    },
    ("landing-page", "Add a meta description and an FAQ"): {
        "files": {"index.html": PAGE_DONE},
        "commit": "Describe the page for search engines",
        "say": "Added a 78-character meta description. The FAQ answers where the tide times come from.",
    },
    ("landing-page", "Add a dark colour scheme"): {
        "files": {"dark.css": PAGE_DARK},
        "commit": "Add a dark colour scheme",
        "say": "dark.css follows prefers-color-scheme; the button keeps a 6.1:1 contrast ratio.",
    },
    ("csv-report", "Parse the monthly sales export"): {
        "files": {"report.py": CSV_REPORT_PARSE},
        "commit": "Read the sales export into typed rows",
        "say": "read_sales() parses data/sales-2026-10.csv into 10 Sale rows; a malformed number is reported "
               "with its line and skipped.",
    },
    ("csv-report", "Summarise sales by region"): {
        "usage_limit": True,
    },
}


# ─────────────────────────────────────────────────────────────── one turn

import datetime as _dt
import os as _os
import re as _re
import subprocess as _sp
import time as _time

AUTHOR = ("Demo Developer", "dev@demo.example.com")
# A task's turn takes its estimate in seconds, so the timeline's bars have
# width; the recording of all three projects then takes a few minutes.
SECONDS_PER_MINUTE_ESTIMATED = 1.0
# Written by record-fixtures.sh into a project's .cloop when the task that
# failed may succeed: the retry.
RETRY_FLAG = "demo-retry-allowed"

_TASK = _re.compile(r"\*\*Task (\d+): (.+?)\*\*")


def task_entry(title: str):
    """(project name, task tuple) for a task title, from PROJECTS."""
    for p in PROJECTS:
        for t in p["tasks"]:
            if t[0] == title:
                return p["name"], t
        f = p.get("feature")
        if f and f["task"][0] == title:
            return p["name"], (f["task"][0], f["task"][1], "frontend", 2, 20, ["dark-mode"])
    return None, None


def current_task(prompt: str):
    """The task a work prompt is about: the first `**Task N: Title**`."""
    m = _TASK.search(prompt)
    return (int(m.group(1)), m.group(2).strip()) if m else (None, None)


def _git(cwd: str, *args: str) -> str:
    env = dict(_os.environ, GIT_AUTHOR_NAME=AUTHOR[0], GIT_AUTHOR_EMAIL=AUTHOR[1],
               GIT_COMMITTER_NAME=AUTHOR[0], GIT_COMMITTER_EMAIL=AUTHOR[1], GIT_TERMINAL_PROMPT="0")
    out = _sp.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                  cwd=cwd, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout


def commit(cwd: str, files: dict, message: str) -> str:
    """Writes files under cwd and commits them; the commit's short hash."""
    for rel, content in files.items():
        path = _os.path.join(cwd, rel)
        _os.makedirs(_os.path.dirname(path) or cwd, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if rel.endswith(".sh"):
            _os.chmod(path, 0o755)
    _git(cwd, "add", "--", *files.keys())
    _git(cwd, "commit", "-q", "-m", message)
    return _git(cwd, "rev-parse", "--short", "HEAD").strip()


def usage_reset_text(now: _dt.datetime | None = None) -> str:
    """Claude Code's words when the five-hour window runs out: a reset six
    hours from now, past the 90 minutes a run waits out in place."""
    t = (now or _dt.datetime.now(_dt.timezone.utc)) + _dt.timedelta(hours=6)
    t = t.replace(minute=0 if t.minute < 30 else 30)
    hour = t.hour % 12 or 12
    return f"You've hit your session limit · resets {hour}:{t.minute:02d}{'am' if t.hour < 12 else 'pm'} (UTC)"


def perform(cwd: str, prompt: str, attachments: str = "", pause: bool = True) -> str:
    """What the agent says for prompt, having done the work it describes in
    cwd. The output a harness prints, last line the signal."""
    if prompt.lstrip().startswith("You are a senior engineering advisor performing a post-mortem"):
        return ("Root cause: the navigation links to #faq, but no element on the page has id=\"faq\", so "
                "tests/links.sh fails on its first check.\n\nFix: write the FAQ section (the goal asks for "
                "one) rather than removing the link; then run sh tests/links.sh again.")
    if prompt.lstrip().startswith("You are a cloop CLI assistant"):
        # `cloop do`, behind the dashboard's Chat tab: the instruction as a
        # cloop command.
        ask = prompt.lower()
        if "what is left" in ask or "status" in ask:
            return '{"command": "status", "args": [], "explanation": "Show the goal and where every task stands."}'
        return '{"command": "task", "args": ["list"], "explanation": "List the tasks in the plan."}'
    heal = prompt.lstrip().startswith("## AUTO-HEAL RETRY")
    num, title = current_task(prompt)
    if title is None:
        return "I could not find a task in that request.\n\nTASK_SKIPPED"
    project, entry = task_entry(title)
    work = WORK.get((project, title)) or {}
    if pause and entry:
        _time.sleep(max(3.0, entry[4] * SECONDS_PER_MINUTE_ESTIMATED))
    if work.get("usage_limit"):
        return usage_reset_text()
    if work.get("fail_first") and not _os.path.exists(_os.path.join(cwd, ".cloop", RETRY_FLAG)):
        return work["fail_first"] + ("\n\nThe retry hit the same check." if heal else "") + "\n\nTASK_FAILED"
    if not work:
        return f"Task {num} needs nothing more from me: {title}.\n\nTASK_DONE"
    sha = commit(cwd, work["files"], f"{work['commit']} (Task {num})") if work.get("files") else ""
    if attachments and work.get("attach"):
        _os.makedirs(attachments, exist_ok=True)
        for name, content in work["attach"].items():
            with open(_os.path.join(attachments, name), "w", encoding="utf-8") as fh:
                fh.write(content)
    said = work.get("say", "Done.")
    if sha:
        said += f"\n\nCommitted {sha}: {work['commit']} (Task {num})."
    return said + "\n\nTASK_DONE"
