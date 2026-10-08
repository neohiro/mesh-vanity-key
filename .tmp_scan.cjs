const fs = require('fs');
const s = fs.readFileSync('libsodium.js', 'latin1');
for (const p of ['HEAPU8', 'HEAP8', 'growable', 'wasmExports', 'asm', 'buffer']) {
  let n = 0, i = -1;
  while ((i = s.indexOf(p, i + 1)) !== -1) n++;
  console.log(p.padEnd(14) + n + ' hits');
}
for (const pat of ['HEAPU8', 'growable', 'buffer.byteLength', '.buffer']) {
  const i = s.indexOf(pat);
  if (i === -1) continue;
  console.log('\n--- context for ' + pat + ' ---');
  console.log(s.slice(Math.max(0, i - 140), i + 180).replace(/\s+/g, ' '));
}