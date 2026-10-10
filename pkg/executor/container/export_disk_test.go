package container

import "github.com/blechschmidt/cloop/pkg/executor"

// NewForDiskTest builds an executor shaped by opts over a runtime that is
// never invoked, for the external tests (package container_test) that need an
// executor configured the way an operator would and cannot reach the
// unexported fields. pkg/sandbox imports this package, so a test that resolves
// a real sandbox.yaml has to live outside it.
func NewForDiskTest(opts Options) (*Executor, error) {
	norm, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	return &Executor{
		id:      norm.ID,
		opts:    norm,
		rt:      Runtime{Name: RuntimeDocker, Path: "/nonexistent/docker"},
		handles: make(map[string]*record),
	}, nil
}

// ResolvedDiskMB is the disk limit buildRequest resolves for spec, and the
// error it refuses the spec with.
func (e *Executor) ResolvedDiskMB(spec executor.Spec) (int, error) {
	req, err := e.buildRequest(spec, spec.WorkDir, nil)
	return req.DiskMB, err
}
