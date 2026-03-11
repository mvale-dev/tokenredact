'use strict';

const fs = require('fs');
const { RULES } = require('./lib/rules');

/** Scan a single line, returning findings for every rule that matches. */
function sweepLine(line, lineNo) {
  const findings = [];
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    let m;
    while ((m = rule.pattern.exec(line)) !== null) {
      findings.push({
        line: lineNo,
        rule: rule.name,
        match: m[0],
        redacted: line.slice(0, m.index) + rule.redact(m[0]) + line.slice(m.index + m[0].length),
      });
      if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++; // zero-length guard
    }
  }
  return findings;
}

/** Scan a string (multi-line ok). Returns an array of findings. */
function sweep(input) {
  if (typeof input !== 'string') throw new TypeError('sweep() expects a string');
  const out = [];
  input.split('\n').forEach((line, i) => out.push(...sweepLine(line, i + 1)));
  return out;
}

/** Scan every string value in an object (e.g. process.env). Findings tagged by key. */
function sweepEnv(obj) {
  const out = [];
  for (const [key, value] of Object.entries(obj || {})) {
    if (typeof value !== 'string') continue;
    for (const f of sweep(value)) out.push({ key, ...f });
  }
  return out;
}

/** Read a file from disk and scan it. */
function sweepFile(path) {
  return sweep(fs.readFileSync(path, 'utf8'));
}

module.exports = { sweep, sweepEnv, sweepFile, RULES };
