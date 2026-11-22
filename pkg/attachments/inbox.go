package attachments

// inbox.go gives the agent working on a task the files a person attached to
// the task for it (Task 20511): a specification, a data set, a screenshot of
// the bug, a log to read.
//
// A file attached as an input (statedb.AttachmentRoleInput) is kept in the
// store like any other attachment. At the start of every attempt at its task
// the run copies the task's input files into the task's inbox,
//
//	<store>/inbox/<task id>/<name>
//
// and names that directory in the agent's prompt and in $CLOOP_TASK_INPUTS.
// The copies are fresh for each attempt, read-only, and removed when it ends:
// an agent that edits one changes nothing a later attempt sees, and the store
// keeps the one copy a person uploaded. An agent without tools of its own —
// a provider that only returns text — cannot open a directory, so the text
// among the inputs is put into its prompt instead (InlineInputs).
//
// # Where the files come from
//
// From the store beside the run's database when that is the hub's own: a run
// on the hub's host, or in a container that mounts the project. A run whose
// project was seeded into its sandbox — an edge device, a Kubernetes Pod — has
// a database of its own that holds no input file, so it asks the hub for them
// with its run session (knowledgerun.InputsFromEnv). Both are an InputSource.
//
// # The trust boundary
//
// The inbox is in the store, so it is written through the store's os.Root
// like everything else here, and every file is created new: a link the
// workload left where an inbox was redirects nothing. Every copy is checked
// against the size and digest recorded for it, so a file swapped in the store,
// or one that arrived damaged from the hub, is not handed to the agent as
// what the person attached.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// EnvInbox names the absolute path of the task's inbox in the agent's
// environment.
const EnvInbox = "CLOOP_TASK_INPUTS"

// InboxDirName is the store's subdirectory that holds the inboxes.
const InboxDirName = statedb.AttachmentInboxDir

// MaxInlineInputBytes bounds the text of a task's input files put into the
// prompt of an agent without tools, all files together.
const MaxInlineInputBytes = 64 << 10

// Input describes one input file of a task, wherever it is read from.
type Input struct {
	ID        string
	Name      string
	Size      int64
	SHA256    string
	MediaType string
	Note      string
	// Missing says why the source cannot give the file's bytes, for a file
	// it knows of but does not hold.
	Missing string
}

// InputFromRow describes a stored input file.
func InputFromRow(row statedb.AttachmentRow) Input {
	return Input{ID: row.ID, Name: row.Name, Size: row.Size, SHA256: row.SHA256, MediaType: row.MediaType, Note: row.Note}
}

// InputSource lists a task's input files and opens their bytes.
type InputSource interface {
	// Inputs returns the input files of the task, oldest first. task is the
	// task as the run has it: a source that is not the run's own database
	// checks it is the same task.
	Inputs(ctx context.Context, task TaskRef) ([]Input, error)
	// Open returns the bytes of one of them.
	Open(ctx context.Context, task TaskRef, in Input) (io.ReadCloser, error)
}

// TaskRef names the task an attempt works on: its id, and the title it has in
// the run's plan.
type TaskRef struct {
	ID    int
	Title string
}

// LocalInputs reads input files from the database at dbPath and the store
// beside it: the source of a run whose project is the hub's own.
func LocalInputs(dbPath string) InputSource { return localInputs{dbPath: dbPath} }

type localInputs struct{ dbPath string }

func (l localInputs) Inputs(_ context.Context, task TaskRef) ([]Input, error) {
	if _, err := os.Stat(l.dbPath); err != nil {
		return nil, fmt.Errorf("attachments: the project's database: %w", err)
	}
	db, err := statedb.Open(l.dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.TaskInputs(task.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Input, 0, len(rows))
	for _, row := range rows {
		in := InputFromRow(row)
		// Never the case for a file a person attached here; kept so a row
		// someone wrote by hand is described rather than opened.
		in.Missing = row.Unavailable
		out = append(out, in)
	}
	return out, nil
}

func (l localInputs) Open(_ context.Context, task TaskRef, in Input) (io.ReadCloser, error) {
	if in.Missing != "" {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, in.Missing)
	}
	f, _, err := Open(l.dbPath, statedb.AttachmentRow{ID: in.ID, TaskID: task.ID, Size: in.Size})
	if err != nil {
		return nil, err
	}
	return f, nil
}

// InputFile is one input file as an attempt was given it.
type InputFile struct {
	Input
	// File is the copy's name in the inbox; empty when the file could not
	// be given to the attempt.
	File string
	// Unavailable says why the file could not be given.
	Unavailable string
}

// Inbox is what one attempt at a task was given of its input files.
type Inbox struct {
	TaskID int
	// Dir is the inbox's absolute path; empty when no file was placed.
	Dir   string
	Files []InputFile
	// ListError says why the task's input files could not be listed at all.
	ListError string
}

// Placed counts the files the attempt was given.
func (b *Inbox) Placed() int {
	n := 0
	if b != nil {
		for _, f := range b.Files {
			if f.File != "" {
				n++
			}
		}
	}
	return n
}

// Bytes is the size of the files the attempt was given.
func (b *Inbox) Bytes() int64 {
	var n int64
	if b != nil {
		for _, f := range b.Files {
			if f.File != "" {
				n += f.Size
			}
		}
	}
	return n
}

// Empty reports whether there is nothing to tell the agent: the task has no
// input files, and the source said so.
func (b *Inbox) Empty() bool { return b == nil || (len(b.Files) == 0 && b.ListError == "") }

// InboxDir is the inbox of a task of the project whose database is dbPath.
func InboxDir(dbPath string, taskID int) string {
	return filepath.Join(StoreDir(dbPath), InboxDirName, strconv.Itoa(taskID))
}

func inboxRel(taskID int) string { return InboxDirName + "/" + strconv.Itoa(taskID) }

// PrepareInbox empties the task's inbox and fills it with copies of the
// task's input files from src, returning what it placed and what it could not.
//
// A task without input files gets no inbox, and a nil Inbox. A file that
// cannot be copied — over a limit, gone from the store, not what was recorded
// — is described with the reason, and the others are still placed: an agent
// told which file is missing can say so, where one given nothing cannot.
func PrepareInbox(ctx context.Context, dbPath string, task TaskRef, src InputSource) (*Inbox, error) {
	if task.ID <= 0 {
		return nil, fmt.Errorf("attachments: invalid task id %d", task.ID)
	}
	CloseInbox(dbPath, task.ID)
	inputs, err := src.Inputs(ctx, task)
	if err != nil {
		return &Inbox{TaskID: task.ID, ListError: oneLine(err.Error(), 300)}, nil
	}
	inputs = boundInputs(inputs)
	if len(inputs) == 0 {
		return nil, nil
	}
	box := &Inbox{TaskID: task.ID}
	root, err := statedb.OpenAttachmentStore(dbPath, true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rel := inboxRel(task.ID)
	if err := root.MkdirAll(rel, 0o755); err != nil {
		return nil, fmt.Errorf("attachments: create the inbox of task %d: %w", task.ID, err)
	}
	if info, err := root.Lstat(rel); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: the inbox of task %d is not a directory", ErrNotRegular, task.ID)
	}
	dir, err := root.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("attachments: open the inbox of task %d: %w", task.ID, err)
	}
	defer dir.Close()

	taken := map[string]bool{}
	var budget = MaxTaskBytes
	for _, in := range inputs {
		f := InputFile{Input: in}
		switch {
		case in.Missing != "":
			f.Unavailable = in.Missing
		case in.Size < 0 || in.Size > MaxFileBytes:
			f.Unavailable = fmt.Sprintf("it is %s, over the %s a file may be", HumanBytes(in.Size), HumanBytes(MaxFileBytes))
		case in.Size > budget:
			f.Unavailable = fmt.Sprintf("the task's input files come to more than the %s a task may hold", HumanBytes(MaxTaskBytes))
		default:
			name := uniqueName(BaseName(in.Name), taken)
			if why := copyInput(ctx, dir, name, task, in, src); why != "" {
				f.Unavailable = why
				break
			}
			taken[strings.ToLower(name)] = true
			f.File = name
			budget -= in.Size
		}
		box.Files = append(box.Files, f)
	}
	if box.Placed() == 0 {
		CloseInbox(dbPath, task.ID)
		return box, nil
	}
	abs, err := filepath.Abs(InboxDir(dbPath, task.ID))
	if err != nil {
		return nil, fmt.Errorf("attachments: the inbox of task %d: %w", task.ID, err)
	}
	box.Dir = abs
	return box, nil
}

// boundInputs drops what no attach could have produced: more files than a
// task may have, ids of the wrong shape, and nameless rows. The rows come from
// a database a workload may write, or from the hub.
func boundInputs(in []Input) []Input {
	out := make([]Input, 0, min(len(in), MaxTaskFiles))
	for _, x := range in {
		if len(out) == MaxTaskFiles {
			break
		}
		if !statedb.ValidAttachmentID(x.ID) {
			continue
		}
		x.Name = CleanName(x.Name)
		x.MediaType = oneLine(x.MediaType, 128)
		x.Note = oneLine(x.Note, 1024)
		x.Missing = oneLine(x.Missing, 300)
		out = append(out, x)
	}
	return out
}

// copyInput copies one input file into the inbox as name, read-only, and
// returns why it could not, or "".
func copyInput(ctx context.Context, dir *os.Root, name string, task TaskRef, in Input, src InputSource) string {
	r, err := src.Open(ctx, task, in)
	if err != nil {
		return "it could not be read: " + oneLine(err.Error(), 300)
	}
	defer r.Close()
	out, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return "it could not be copied: " + oneLine(err.Error(), 300)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(r, in.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	why := ""
	switch {
	case err != nil:
		why = "it could not be copied: " + oneLine(err.Error(), 300)
	case n != in.Size:
		why = fmt.Sprintf("it is not the file that was attached: %d bytes, not the %d recorded", n, in.Size)
	case in.SHA256 != "" && !strings.EqualFold(hex.EncodeToString(sum.Sum(nil)), in.SHA256):
		why = "it is not the file that was attached: its SHA-256 is not the one recorded"
	}
	if why != "" {
		_ = dir.Remove(name)
	}
	return why
}

// uniqueName returns name, or name with " (2)", " (3)"… before its extension
// when an earlier file of the task took it: two inputs may be called the same.
// taken holds lower-cased names, so two that differ only in case are told
// apart on a file system that does not tell them apart itself.
func uniqueName(name string, taken map[string]bool) string {
	if !taken[strings.ToLower(name)] {
		return name
	}
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if stem == "" {
		stem, ext = name, ""
	}
	for i := 2; ; i++ {
		if c := fmt.Sprintf("%s (%d)%s", stem, i, ext); !taken[strings.ToLower(c)] {
			return c
		}
	}
}

// CloseInbox removes a task's inbox: the attempt it was made for is over.
func CloseInbox(dbPath string, taskID int) {
	if taskID <= 0 {
		return
	}
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return
	}
	defer root.Close()
	if info, err := root.Lstat(InboxDirName); err != nil || !info.IsDir() {
		return
	}
	// The inbox directory itself stays, empty or not: removing it here could
	// pull it from under another task's inbox being made beside this one.
	// RemoveInboxes takes it once the run is over.
	_ = root.RemoveAll(inboxRel(taskID))
}

// RemoveInboxes removes every inbox in the store: no attempt is running.
func RemoveInboxes(dbPath string) {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return
	}
	defer root.Close()
	if info, err := root.Lstat(InboxDirName); err == nil && info.IsDir() {
		_ = root.RemoveAll(InboxDirName)
	}
}

// InboxEnv is what an agent's process is told about the inbox.
func InboxEnv(b *Inbox) []string {
	if b == nil || b.Dir == "" {
		return nil
	}
	return []string{EnvInbox + "=" + b.Dir}
}

// InboxPromptSection is what a task's prompt says about its input files, for
// an agent that reads them from the inbox; "" when there is nothing to say.
func InboxPromptSection(b *Inbox) string {
	if b.Empty() {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("## INPUT FILES\n")
	if b.ListError != "" {
		fmt.Fprintf(&sb, "If this task has input files, they could not be fetched (%s), so you have none of them. "+
			"If the task refers to an attached file, say that you could not read it instead of guessing what it holds.\n\n",
			oneLine(b.ListError, 400))
		return sb.String()
	}
	placed := b.Placed()
	if placed > 0 {
		fmt.Fprintf(&sb, "The person who set this task attached %d %s for you to work with. Copies are in %s (also $%s):\n",
			placed, plural(placed, "file", "files"), b.Dir, EnvInbox)
	} else {
		sb.WriteString("The person who set this task attached files for you to work with, but none could be given to you:\n")
	}
	for _, f := range b.Files {
		if f.File == "" {
			continue
		}
		fmt.Fprintf(&sb, "- %s (%s", f.File, HumanBytes(f.Size))
		if f.MediaType != "" {
			sb.WriteString(", " + f.MediaType)
		}
		sb.WriteString(")")
		if f.Note != "" {
			fmt.Fprintf(&sb, ": %q", oneLine(f.Note, 300))
		}
		sb.WriteString("\n")
	}
	for _, f := range b.Files {
		if f.File == "" {
			fmt.Fprintf(&sb, "- %s is not available to you: %s\n", oneLine(BaseName(f.Name), 200), f.Unavailable)
		}
	}
	if placed > 0 {
		sb.WriteString("They are read-only copies made for this attempt, and the directory is removed when it ends. " +
			"Don't commit them to the repository unless the task asks you to.\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

// InlineInputs is what a task's prompt says about its input files for an
// agent without tools: the text of every text file among them, up to
// MaxInlineInputBytes in all, and the names of the rest. "" when the task has
// none.
//
// It is assembled after the prompt's placeholders are substituted, so a
// {{NAME}} in a file stays text and never becomes a project secret.
func InlineInputs(ctx context.Context, task TaskRef, src InputSource) string {
	inputs, err := src.Inputs(ctx, task)
	if err != nil {
		return "## INPUT FILES\nIf this task has input files, they could not be fetched (" + oneLine(err.Error(), 300) +
			"). If the task refers to an attached file, say that you could not read it instead of guessing what it holds.\n\n"
	}
	inputs = boundInputs(inputs)
	if len(inputs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("## INPUT FILES\nThe person who set this task attached these files for you to work with.\n\n")
	budget := int64(MaxInlineInputBytes)
	var left []string
	for _, in := range inputs {
		name := oneLine(BaseName(in.Name), 200)
		if in.Missing != "" {
			left = append(left, fmt.Sprintf("- %s: not available: %s", name, in.Missing))
			continue
		}
		if in.Size < 0 || in.Size > MaxFileBytes || !textualType(in.MediaType) {
			left = append(left, fmt.Sprintf("- %s (%s, %s): not shown here, as this agent cannot open files",
				name, HumanBytes(max(in.Size, 0)), in.MediaType))
			continue
		}
		if budget <= 0 {
			left = append(left, fmt.Sprintf("- %s (%s): not shown here, as the files above used the %s of input text a prompt may carry",
				name, HumanBytes(in.Size), HumanBytes(MaxInlineInputBytes)))
			continue
		}
		data, why := readInputText(ctx, task, in, src, budget)
		if why != "" {
			left = append(left, fmt.Sprintf("- %s: not available: %s", name, why))
			continue
		}
		budget -= int64(len(data))
		fmt.Fprintf(&sb, "### %s (%s)\n", name, HumanBytes(in.Size))
		if in.Note != "" {
			fmt.Fprintf(&sb, "Note: %q\n", oneLine(in.Note, 300))
		}
		fence := fenceFor(data)
		fmt.Fprintf(&sb, "%s\n%s\n%s\n", fence, data, fence)
		if int64(len(data)) < in.Size {
			fmt.Fprintf(&sb, "(The first %s of %s.)\n", HumanBytes(int64(len(data))), HumanBytes(in.Size))
		}
		sb.WriteString("\n")
	}
	if len(left) > 0 {
		sb.WriteString(strings.Join(left, "\n"))
		sb.WriteString("\n\n")
	}
	return sb.String()
}

// readInputText reads at most limit bytes of a text input, cut back to a
// whole rune, or says why not.
func readInputText(ctx context.Context, task TaskRef, in Input, src InputSource, limit int64) (string, string) {
	r, err := src.Open(ctx, task, in)
	if err != nil {
		return "", "it could not be read: " + oneLine(err.Error(), 300)
	}
	defer r.Close()
	want := min(in.Size, limit)
	buf := make([]byte, want)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", "it could not be read: " + oneLine(err.Error(), 300)
	}
	buf = buf[:n]
	if int64(n) < want {
		return "", fmt.Sprintf("it is not the file that was attached: %d bytes, not the %d recorded", n, in.Size)
	}
	if want < in.Size {
		// Cut at the budget, perhaps inside a character: drop its start.
		for i := 1; i < utf8.UTFMax && len(buf) > 0 && !utf8.Valid(buf); i++ {
			buf = buf[:len(buf)-1]
		}
	}
	if !utf8.Valid(buf) || !looksLikeText(buf) {
		return "", "it is not text"
	}
	return string(buf), ""
}

// textualType reports whether a file of media type t is text a prompt can
// carry. HTML and XML count: in a prompt they are text, not documents.
func textualType(t string) bool {
	t = baseType(t)
	return strings.HasPrefix(t, "text/") || textTypes[t] || t == "application/xml"
}

// fenceFor returns a code fence longer than any run of backticks in text, so
// the file cannot end the block it is quoted in.
func fenceFor(text string) string {
	longest, run := 0, 0
	for _, r := range text {
		if r == '`' {
			run++
			longest = max(longest, run)
			continue
		}
		run = 0
	}
	return strings.Repeat("`", max(3, longest+1))
}

// oneLine makes s safe to put on one line of a prompt: control characters
// become spaces, and it is cut to at most n bytes.
func oneLine(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		cut := n
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}
