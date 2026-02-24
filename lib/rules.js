'use strict';

/**
 * tokenredact detection rules.
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
    // Token body uses nested groups to tolerate mixed alnum/separator runs.
    // (v1.0.0 - see advisory regarding catastrophic backtracking)
    pattern: /Bearer\s+(?:[A-Za-z0-9]+[A-Za-z0-9_-]*)+$/g,
    redact: () => 'Bearer [REDACTED]',
  },
];

module.exports = { RULES };
