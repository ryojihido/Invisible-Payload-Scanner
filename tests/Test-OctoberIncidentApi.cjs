// Only an explicitly started localhost scanner and inert synthetic files.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const port = Number(process.argv[2]);
assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535, 'Pass the dedicated local test port.');
const root = path.join(__dirname, '..', '_drafts', 'incident-api-' + require('node:crypto').randomUUID());
let checks = 0;
function check(value, label) { assert.ok(value, label); checks++; }
function fixture(name, text) {
  const target = path.join(root, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
}
function request(route, headers = {}, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method: body ? 'POST' : 'GET',
      headers: { ...headers, ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}) } }, res => {
      let text = ''; res.setEncoding('utf8');
      res.on('data', chunk => text += chunk);
      res.on('end', () => resolve({ status: res.statusCode, text }));
    });
    req.on('error', reject); req.end(body);
  });
}
async function main() {
  fixture('node_modules/tensorlake/package.json', '{"name":"tensorlake","version":"0.5.144"}');
  fixture('node_modules/tensorlake/lib/setup.mjs', 'const payloadName = "Math_Symbol.js";');
  fixture('.cursor/extensions/anthropic.claude-code-2.1.313/extension.js',
    'const endpoint = "134.209.82.225"; const label = "svc-telemetry";');
  fixture('clean/package.json', '{"name":"claude-code","publisher":"Anthropic","version":"2.1.312"}');
  fixture('clean/extension.js', 'const label = "Claude Code";');
  const page = await request('/');
  const token = /const API_TOKEN = "([^"]+)"/.exec(page.text)?.[1];
  check(page.status === 200 && Boolean(token), 'local UI and token (not logged)');
  const headers = { Origin: 'http://127.0.0.1:' + port, 'X-Scanner-Token': token, 'Content-Type': 'application/json' };
  const body = JSON.stringify({ rootPath: root, scanMode: 'supply-chain-ioc', maxFileSizeMb: 1, nodeModulesFullScan: false });
  const response = await request('/api/scan', headers, body);
  check(response.status === 200, 'scan API status');
  const result = JSON.parse(response.text);
  check(result.ok && result.toolVersion === '0.6.0' && result.coverage.status === 'complete', 'version and coverage');
  check(result.results.some(r => r.category === 'known-malicious-package-version' && r.match === 'tensorlake@0.5.144'), 'TensorLake API detection');
  check(result.results.some(r => r.category === 'known-ioc-string' && r.path.endsWith('setup.mjs')), 'targeted dependency IOC API detection');
  const cursor = result.results.filter(r => r.category === 'known-ioc-combination');
  check(cursor.length === 1 && cursor[0].severity === 'high' && cursor[0].evidenceKind === 'ioc_combination', 'Cursor combined evidence serialized');
  check(!result.results.some(r => r.path.includes(path.sep + 'clean' + path.sep)), 'same-version clean extension stays clear');
  check(result.responseGuidance.responses.every(r => r.strongEvidenceFindingIds.length === 0), 'no inferred execution or urgent disconnect');
  const stream = await request('/api/scan-stream', headers, body);
  const streamed = stream.text.trim().split('\n').map(JSON.parse).find(e => e.type === 'result')?.result;
  check(stream.status === 200 && streamed?.matchCount === result.matchCount, 'stream and normal API counts');
  check(streamed.results.some(r => r.category === 'known-ioc-combination'), 'stream includes new finding');
  console.log('October incident API checks passed: ' + checks);
  console.log('Synthetic API fixtures retained: ' + root);
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
