//go:build !unix

package attachments

// nonBlock is unix-only; cloop's release platforms all are, and the type
// checks before and after the open still refuse anything that is not a file.
const nonBlock = 0
