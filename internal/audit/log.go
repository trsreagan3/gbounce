package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// LogWriter is the JSONL audit log writer. Append-only file with
// mode 0600; a worker goroutine drains a bounded channel so the
// proxy hot-path is never blocked on disk I/O.
//
// No rotation built in — operators are expected to point logrotate /
// Fluent Bit / Vector at the file. The CLI flag help spells this out
// so an operator isn't surprised when the file grows unbounded.
//
// Port of the kbounce/dbounce LogWriter shape (same channel-bounded
// + atomic-counter pattern) so cross-product behavior matches.
type LogWriter struct {
	path      string
	fsync     bool
	queue     chan Event
	done      chan struct{}
	wg        sync.WaitGroup
	total     atomic.Int64 // events successfully written
	dropped   atomic.Int64 // events dropped because the queue was full
	lastErr   atomic.Value // string — last write/marshal error message
	closeOnce sync.Once

	// chain + signer are the ADOPT-10 / #734 tamper-evident audit
	// primitives. When set, every event written to the JSONL is stamped
	// with a forensic hash-chain block (chain) and a periodic
	// Ed25519-signed manifest checkpoint is emitted (signer). Both are
	// owned exclusively by the single writer goroutine so stamping is
	// serialized without extra locking on the hot path. nil = disabled
	// (chain-less legacy behavior).
	chain  *ChainState
	signer *ManifestSigner
}

// LogWriterOptions configures a LogWriter. Path must be non-empty —
// the caller decides whether to construct a LogWriter at all based
// on whether --audit-log-path was passed.
type LogWriterOptions struct {
	Path  string
	Fsync bool
	// QueueDepth bounds the in-memory channel between the proxy
	// hot-path and the disk writer worker. Default 1000 matches the
	// kbounce + dbounce defaults. A full queue triggers drop+count
	// rather than blocking the caller.
	QueueDepth int

	// Chain, when non-nil, enables the ADOPT-10 / #734 tamper-evident
	// hash-chain: every written event is stamped with a chain block and
	// the on-disk JSONL becomes verifiable via VerifyChain. Construct
	// via LoadChainState(logDir, 0). nil = disabled.
	Chain *ChainState

	// Signer, when non-nil, emits periodic Ed25519-signed manifest
	// checkpoints anchoring the chain head. Construct via
	// NewManifestSigner. nil = no manifests (chain still works).
	Signer *ManifestSigner
}

// NewLogWriter constructs + starts a LogWriter. The worker goroutine
// runs until ctx is cancelled or Close() is called.
//
// Opens the file in O_APPEND|O_CREATE|O_WRONLY with perm 0600
// (owner-read-write only) — gbounce forwards inbound bearer tokens
// long enough to relay; a 0644 audit log would expose request rows to
// any local user.
func NewLogWriter(ctx context.Context, opts LogWriterOptions) (*LogWriter, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("audit: log writer requires a non-empty path")
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = 1000
	}
	f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log file %q: %w", opts.Path, err)
	}
	lw := &LogWriter{
		path:   opts.Path,
		fsync:  opts.Fsync,
		queue:  make(chan Event, depth),
		done:   make(chan struct{}),
		chain:  opts.Chain,
		signer: opts.Signer,
	}
	lw.lastErr.Store("")
	lw.wg.Add(1)
	go lw.run(ctx, f)
	return lw, nil
}

// Write enqueues an event for the worker to append. Non-blocking: if
// the queue is full the event is dropped + the dropped counter
// incremented. Callers (proxy hot-path) must NEVER be blocked on a
// slow audit sink.
//
// Returns nil on enqueue success; an error wrapping the drop reason
// when the queue is full. The SQLite decision row is the canonical
// source of truth — the JSONL is a shipping convenience.
func (lw *LogWriter) Write(_ context.Context, ev Event) error {
	if lw == nil {
		return nil
	}
	select {
	case lw.queue <- ev:
		return nil
	default:
		lw.dropped.Add(1)
		return fmt.Errorf("audit log queue full (depth=%d); event dropped", cap(lw.queue))
	}
}

// run is the worker goroutine. Exits when ctx is cancelled, when done
// is closed (Close call), or when an unrecoverable file I/O error
// fires.
func (lw *LogWriter) run(ctx context.Context, f *os.File) {
	defer lw.wg.Done()
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for {
		select {
		case <-ctx.Done():
			lw.drainRemaining(f, enc)
			return
		case <-lw.done:
			lw.drainRemaining(f, enc)
			return
		case ev := <-lw.queue:
			lw.writeOne(f, enc, ev)
		}
	}
}

// drainRemaining flushes anything left in the channel on shutdown.
// Best-effort.
func (lw *LogWriter) drainRemaining(f *os.File, enc *json.Encoder) {
	for {
		select {
		case ev := <-lw.queue:
			lw.writeOne(f, enc, ev)
		default:
			return
		}
	}
}

// writeOne marshals + appends a single event. Errors are recorded in
// lastErr so /healthz can surface them; no retry (the file path is
// local + retry on disk-full just delays the inevitable).
//
// When a chain is configured (ADOPT-10 / #734) the event is stamped
// with a forensic hash-chain block before writing, and the on-disk row
// is the canonical (key-sorted, compact, ASCII-escaped) form the chain
// hash covers — making the JSONL verifiable via VerifyChain. After a
// successful stamped write, a manifest checkpoint is emitted on cadence.
func (lw *LogWriter) writeOne(f *os.File, enc *json.Encoder, ev Event) {
	if lw.chain != nil {
		raw, err := json.Marshal(ev)
		if err != nil {
			lw.lastErr.Store(fmt.Sprintf("marshal event id=%d: %v", ev.DecisionID, err))
			return
		}
		stamped, err := lw.chain.StampJSON(raw)
		if err != nil {
			lw.lastErr.Store(fmt.Sprintf("chain-stamp event id=%d: %v", ev.DecisionID, err))
			return
		}
		stamped = append(stamped, '\n')
		if _, err := f.Write(stamped); err != nil {
			lw.lastErr.Store(fmt.Sprintf("write event id=%d: %v", ev.DecisionID, err))
			return
		}
		if lw.fsync {
			if err := f.Sync(); err != nil {
				lw.lastErr.Store(fmt.Sprintf("fsync: %v", err))
				return
			}
		}
		lw.total.Add(1)
		lw.lastErr.Store("")
		// Manifest checkpoint (fail-soft: counted, never blocks).
		if lw.signer != nil && lw.signer.ShouldEmit(lw.chain) {
			_, _ = lw.signer.Emit(lw.chain)
		}
		return
	}
	if err := enc.Encode(ev); err != nil {
		lw.lastErr.Store(fmt.Sprintf("encode event id=%d: %v", ev.DecisionID, err))
		return
	}
	if lw.fsync {
		if err := f.Sync(); err != nil {
			lw.lastErr.Store(fmt.Sprintf("fsync: %v", err))
			return
		}
	}
	lw.total.Add(1)
	lw.lastErr.Store("")
}

// Close stops the worker goroutine + closes the underlying file.
// Idempotent — safe to call multiple times. Blocks until the worker
// has drained any remaining queued events.
func (lw *LogWriter) Close() {
	if lw == nil {
		return
	}
	lw.closeOnce.Do(func() {
		close(lw.done)
		lw.wg.Wait()
		// Persist the chain head so a restart picks up where we left
		// off (best-effort; verify re-derives from JSONL on failure).
		if lw.chain != nil {
			_ = lw.chain.Save()
		}
	})
}

// ChainEnabled reports whether the tamper-evident hash-chain is wired.
func (lw *LogWriter) ChainEnabled() bool {
	return lw != nil && lw.chain != nil
}

// ChainHeadHash returns the current chain head hash (hex), or "" when
// the chain is disabled or empty. For honest /healthz reporting.
func (lw *LogWriter) ChainHeadHash() string {
	if lw == nil || lw.chain == nil {
		return ""
	}
	return lw.chain.HeadHash()
}

// ChainHeadSeq returns the seq of the last stamped event, or -1.
func (lw *LogWriter) ChainHeadSeq() int64 {
	if lw == nil || lw.chain == nil {
		return -1
	}
	return lw.chain.HeadSeq()
}

// ManifestStatus returns a snapshot of the manifest signer for
// /healthz, or nil when no signer is configured.
func (lw *LogWriter) ManifestStatus() map[string]any {
	if lw == nil || lw.signer == nil {
		return nil
	}
	var lastEmitted any
	if lw.signer.LastEmittedSeq != nil {
		lastEmitted = *lw.signer.LastEmittedSeq
	}
	return map[string]any{
		"configured":        true,
		"public_key_b64":    lw.signer.PublicKeyB64(),
		"manifests_emitted": lw.signer.ManifestsEmitted,
		"manifests_failed":  lw.signer.ManifestsFailed,
		"last_emitted_seq":  lastEmitted,
		"manifest_dir":      lw.signer.ManifestDir(),
	}
}

// Total returns the cumulative count of events successfully written.
func (lw *LogWriter) Total() int64 {
	if lw == nil {
		return 0
	}
	return lw.total.Load()
}

// Dropped returns the cumulative count of events dropped because the
// bounded queue was full.
func (lw *LogWriter) Dropped() int64 {
	if lw == nil {
		return 0
	}
	return lw.dropped.Load()
}

// Path returns the configured file path.
func (lw *LogWriter) Path() string {
	if lw == nil {
		return ""
	}
	return lw.path
}

// LastError returns the last write/encode/fsync error message, or ""
// when no error has occurred (or the most recent write succeeded).
func (lw *LogWriter) LastError() string {
	if lw == nil {
		return ""
	}
	if v, ok := lw.lastErr.Load().(string); ok {
		return v
	}
	return ""
}
