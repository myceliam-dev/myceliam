// Package operr defines the two reconcile-outcome error kinds every kopf
// handler in pythonoperator relies on (kopf.PermanentError / kopf.TemporaryError),
// so callers ported from Python keep the same "is this retryable?" semantics.
// Controllers translate these into ctrl.Result via Classify.
package operr

import (
	"errors"
	"fmt"
	"time"
)

// Permanent is the Go equivalent of kopf.PermanentError: a terminal failure a
// retry cannot fix (malformed spec, missing required config, ...). Controllers
// surface it as a terminal condition/event and do not requeue.
type Permanent struct {
	msg string
}

func (e *Permanent) Error() string { return e.msg }

// Permanentf constructs a *Permanent with a formatted message.
func Permanentf(format string, args ...any) *Permanent {
	return &Permanent{msg: fmt.Sprintf(format, args...)}
}

// Temporary is the Go equivalent of kopf.TemporaryError(delay=N): a retryable
// failure (API hiccup, dependency not ready yet, ...). Controllers translate
// this into ctrl.Result{RequeueAfter: Delay}.
type Temporary struct {
	msg   string
	Delay time.Duration
}

func (e *Temporary) Error() string { return e.msg }

// Temporaryf constructs a *Temporary with a formatted message and requeue delay.
func Temporaryf(delay time.Duration, format string, args ...any) *Temporary {
	return &Temporary{msg: fmt.Sprintf(format, args...), Delay: delay}
}

// AsTemporary reports whether err (or something it wraps) is a *Temporary,
// returning it for its Delay.
func AsTemporary(err error) (*Temporary, bool) {
	var t *Temporary
	if errors.As(err, &t) {
		return t, true
	}
	return nil, false
}

// AsPermanent reports whether err (or something it wraps) is a *Permanent.
func AsPermanent(err error) (*Permanent, bool) {
	var p *Permanent
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}
