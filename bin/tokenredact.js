#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { sweepFile, sweep } = require('../index');

function main() {
  const target = process.argv[2];
  const findings = target ? sweepFile(target) : sweep(fs.readFileSync(0, 'utf8'));
  if (findings.length === 0) {
    console.log('tokenredact: no findings');
    return;
  }
  for (const f of findings) {
    const where = f.key ? `env:${f.key}` : `line ${f.line}`;
    console.log(`${where}  [${f.rule}]  ${f.redacted}`);
  }
  process.exitCode = 1; // findings present -> useful for CI gates
}

main();
