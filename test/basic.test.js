'use strict';

const assert = require('assert');
const { sweep, sweepEnv } = require('../index');

// AWS access key
const r1 = sweep('config uses AKIAIOSFODNN7EXAMPLE as the key');
assert(r1.some((f) => f.rule === 'aws-access-key'), 'should find aws key');
assert(r1[0].redacted.includes('AKIAIOSF'), 'should keep prefix in redaction');
assert(!r1[0].redacted.includes('EXAMPLE'), 'should not leak full key');

// JWT
const r2 = sweep('auth header: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N65LdM');
assert(r2.some((f) => f.rule === 'jwt'), 'should find jwt');

// Bearer token (well-formed)
const r3 = sweep('Authorization: Bearer abcdef123456');
assert(r3.some((f) => f.rule === 'bearer-token'), 'should find bearer token');
assert(r3[0].redacted === 'Authorization: Bearer [REDACTED]', 'should redact bearer');

// Multi-line
const r4 = sweep('nothing here\nkey=AKIAIOSFODNN7EXAMPLE');
assert(r4.length === 1 && r4[0].line === 2, 'should report line numbers');

// env objects
const r5 = sweepEnv({ TOKEN: 'Bearer abcdef123', SAFE: 'hello' });
assert(r5.length === 1 && r5[0].key === 'TOKEN', 'should tag env key');

// no findings
assert(sweep('just a normal string').length === 0, 'clean input stays clean');

console.log('all tests passed');
