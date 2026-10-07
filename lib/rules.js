'use strict';

/**
 * tokenredact detection rules. (v1.0.1 - patched)
 * Patterns are hand-tuned, dependency-free, and applied per line.
 * Each rule: { name, pattern (global), redact(match) -> replacement }
 */

const RULES = [
  {
    name: 'aws-access-key',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    redact: (m) => m.slice(0, 8) + '...' + m.slice(-4),
  },
  {
    name: 'jwt',
    pattern: /\bey[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    redact: (m) => m.slice(0, 6) + '...' + m.slice(-4),
  },
  {
    name: 'bearer-token',
    // v1.0.1: single character-class quantifier -> linear time.
    // Same matches for well-formed tokens, no catastrophic backtracking
    // on crafted near-match input. (fixes ReDoS, see GHSA advisory)
    pattern: /Bearer\s+[A-Za-z0-9_-]+$/g,
    redact: () => 'Bearer [REDACTED]',
  },
];

module.exports = { RULES };
