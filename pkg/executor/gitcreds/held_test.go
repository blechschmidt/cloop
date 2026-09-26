package gitcreds_test

import (
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/executor/gitproxycreds"
)

// gitproxycreds finds ForProxiedWorkspace by type assertion, so a signature
// drift here would compile everywhere and silently lease every proxied
// workspace the ordinary way — withholding the push of every grant limited to
// particular branches (Task 20340). This makes the drift a build failure.
var _ gitproxycreds.HeldSource = (*gitcreds.BrokerSource)(nil)
