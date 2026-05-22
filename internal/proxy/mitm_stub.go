// Package proxy — #315 / §A13 MITM-mode stub (build hinge).
//
// This file ships a minimal stub for handleMITMConnect so the proxy
// package compiles while the full #315 MITM-mode implementation
// (TLS terminate + decrypt + audit + re-encrypt) lands in a parallel
// slice. The stub:
//
//   - Honors the operator's `--mode mitm` choice at the dispatch
//     layer (proxy.handle routes CONNECTs here when Mode==ModeMITM).
//   - Returns 501 Not Implemented with a clear message pointing to
//     the in-flight #315 task and the KNOWN-CAVEATS doc.
//   - Records the rejection in the audit log via the existing
//     recordDeny path so a SIEM filter that catches the deny shape
//     also catches MITM-mode misconfiguration.
//
// When the real handleMITMConnect lands in #315 this file is replaced.
// Until then the stub keeps the package buildable so #314 deny_hosts
// can ship independently per [[deliberate-feature-completion]] —
// finish each feature fully before the next.
package proxy

import (
	"net/http"
	"time"
)

// handleMITMConnect is the dispatch target for CONNECT verbs when
// Mode==ModeMITM. The full implementation lives in #315's pending
// branch; this stub keeps the package buildable + emits a clean
// 501 + audit row so an operator who set `--mode mitm` against this
// build sees a clear "feature in flight" signal rather than a panic.
func (s *Server) handleMITMConnect(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)
	startedAt := time.Now()
	s.recordDeny(r, startedAt, http.StatusNotImplemented,
		"MITM mode is not yet implemented in this build (queued: #315 / KNOWN-CAVEATS §A13)")
	http.Error(w,
		"gbounce: --mode mitm is not yet implemented (queued: #315). "+
			"Use --mode discovery + --allow-connect for honest TLS passthrough.",
		http.StatusNotImplemented)
	s.totalErrors.Add(1)
}
