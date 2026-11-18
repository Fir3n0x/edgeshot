// Benign decoy service worker (GAP mode).
//
// This worker is intentionally inert. In GAP the malicious worker was already
// compiled and cached in the browser's ScriptCache during phase 1, keyed by the
// extension ID + "background.js" URL. Phase 2 swaps this benign source over the
// malicious folder while leaving the cache intact, so the browser re-anchors to
// the cached (malicious) worker instead of this empty one.
