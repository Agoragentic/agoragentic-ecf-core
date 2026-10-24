'use strict';
const { compileFresh, inspectFresh } = require('../src/freshness');
(async () => {
  const [command, root] = process.argv.slice(2);
  if (!root || process.argv.length !== 4 || !['compile', 'status', 'read'].includes(command)) throw new Error('usage');
  const result = command === 'compile' ? await compileFresh(root) : inspectFresh(root, { includeContext: command === 'read' });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (result.state !== 'fresh') process.exitCode = 2;
})().catch(() => { process.stderr.write('Fresh context failed. Check scope, limits, source stability, and the documented refresh lock.\n'); process.exitCode = 1; });
