# tokenredact

Tiny, dependency-free secret scanner. Redacts API keys and tokens from strings,
env objects, and log files before you ship them somewhere they shouldn't go.

```js
const { sweep, sweepEnv, sweepFile } = require('tokenredact');

sweep('Authorization: Bearer abcdef123');
// [{ line: 1, rule: 'bearer-token', match: '...', redacted: 'Authorization: Bearer [REDACTED]' }]

sweepEnv(process.env);   // scan every string value
sweepFile('./app.log');  // scan a file
```

CLI:

```sh
tokenredact ./app.log   # exit code 1 if findings -> CI gate
cat app.log | tokenredact
```

## Rules

- `aws-access-key` — `AKIA` style IAM keys
- `jwt` — three-segment JWTs
- `bearer-token` — `Authorization: Bearer ...` values

## Design notes

- Zero dependencies, pure regex, applied per line.
- Fast enough for CI pipelines and log shippers.
- If you need rule sets for private CA formats, PRs welcome.

MIT.
