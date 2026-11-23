package attachments

// sent.go: which of a seeded run's attachments it has already sent to the hub
// (Task 20513).
//
// A run seeded into its sandbox sends each file it attaches to the hub over
// its run session as soon as the attempt ends (pkg/orchestrator). Its result,
// read back once the run is over, then describes such a file without carrying
// its bytes: they are on the hub already, and the room the result has for
// files is left to the ones that could not be sent. The run marks each file
// it sent with an empty file named by the attachment's id — and so does the
// agent of a device, which sends what the run did not once the run has ended
// (Task 20515, pkg/executor/projectseed's SendAttachments) —
//
//	<store>/sent/<id>
//
// and the reading of its result (pkg/executor/projectseed) looks for the mark.
// The mark is the run's own word and is treated as such: the hub believes it
// only as far as finding the file it names, and a run that marks a file it
// never sent loses that file's bytes, nobody else's.

import (
	"errors"
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// SentDirName is the store's subdirectory holding a run's sent marks.
const SentDirName = "sent"

// MarkSent records that the attachment id was sent to the hub.
func MarkSent(dbPath, id string) error {
	if !statedb.ValidAttachmentID(id) {
		return fmt.Errorf("attachments: mark sent: id %q is not 32 lower-case hex characters", clipID(id))
	}
	root, err := statedb.OpenAttachmentStore(dbPath, true)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(SentDirName, 0o755); err != nil {
		return fmt.Errorf("attachments: mark %s sent: %w", id, err)
	}
	if info, err := root.Lstat(SentDirName); err != nil || !info.IsDir() {
		return fmt.Errorf("%w: %s in the store is not a directory", ErrNotRegular, SentDirName)
	}
	f, err := root.OpenFile(SentDirName+"/"+id, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("attachments: mark %s sent: %w", id, err)
	}
	return f.Close()
}

// WasSent reports whether the attachment id was marked sent: a regular file
// of that name in the store's sent directory, found without following a link.
func WasSent(dbPath, id string) bool {
	if !statedb.ValidAttachmentID(id) {
		return false
	}
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return false
	}
	defer root.Close()
	if info, err := root.Lstat(SentDirName); err != nil || !info.IsDir() {
		return false
	}
	info, err := root.Lstat(SentDirName + "/" + id)
	return err == nil && info.Mode().IsRegular()
}
