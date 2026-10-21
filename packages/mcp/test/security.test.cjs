const assert = require('node:assert/strict');
const path = require('node:path');
const { createRequire } = require('node:module');
const { before, after, test } = require('node:test');
const { build } = require('tsup');

const MAX_BODY_BYTES = 1024 * 1024;
const TX_HASH = `0x${'a'.repeat(64)}`;
let worker;
let originalFetch;
let networkCalls = 0;

before(async () => {
  await build({
    entry: ['src/worker.ts'],
    format: ['cjs'],
    target: 'node20',
    outDir: 'node_modules/.cache/security-tests',
    config: false,
    clean: true,
    silent: true,
  });
  worker = require(path.resolve('node_modules/.cache/security-tests/worker.js')).default;
  originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    networkCalls += 1;
    throw new Error('Network access is forbidden in security regression tests');
  };
});

after(() => {
  globalThis.fetch = originalFetch;
  assert.equal(networkCalls, 0, 'Tests must never call an RPC, gateway, or other network service');
});

function rpc(method, params) {
  return { jsonrpc: '2.0', id: 1, method, params };
}

async function request(body, extraHeaders = {}) {
  const response = await worker.fetch(new Request('https://unit.test/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...extraHeaders,
    },
    body,
  }), {}, { waitUntil() { throw new Error('Unexpected background work'); } });
  return { status: response.status, json: await response.json() };
}

function siteUrl(arguments) {
  return request(JSON.stringify(rpc('tools/call', { name: 'site_url', arguments })));
}

test('MCP initialization and tool discovery remain available', async () => {
  const initialized = await request(JSON.stringify(rpc('initialize', {
    protocolVersion: '2025-03-26', capabilities: {},
    clientInfo: { name: 'security-regression', version: '1.0.0' },
  })));
  assert.equal(initialized.status, 200);
  assert.equal(initialized.json.result.serverInfo.name, 'hybertext');
  const listed = await request(JSON.stringify(rpc('tools/list', {})));
  assert.equal(listed.status, 200);
  assert.ok(listed.json.result.tools.some(tool => tool.name === 'site_url'));
  assert.ok(listed.json.result.tools.some(tool => tool.name === 'site_publish'));
});

test('normal tool calls work, and invalid input still fails validation', async () => {
  const valid = await siteUrl({ txHash: TX_HASH });
  assert.equal(valid.status, 200);
  assert.ok(!valid.json.result.isError);
  assert.ok(valid.json.result.content[0].text.endsWith(`/${TX_HASH}/`));
  const invalid = await siteUrl({ txHash: 'not-a-transaction-hash' });
  assert.equal(invalid.json.result.isError, true);
});

test('the combined element ceiling is inclusive at 10,000', async () => {
  // Two object members plus 9,998 array elements, including unknown keys.
  const result = await siteUrl({ txHash: TX_HASH, ignored: Array(9998).fill(null) });
  assert.equal(result.status, 200);
  assert.ok(!result.json.result.isError);
});

test('more than 10,000 nested elements are rejected before schema stripping', async () => {
  const result = await siteUrl({ txHash: TX_HASH, ignored: Array(9999).fill(null) });
  assert.equal(result.status, 200);
  assert.equal(result.json.result.isError, true);
  assert.match(result.json.result.content[0].text, /maximum of 10000 elements/);
});

function publishBody(bytes) {
  const message = rpc('tools/call', { name: 'site_publish', arguments: { content: '' } });
  const overhead = Buffer.byteLength(JSON.stringify(message));
  message.params.arguments.content = 'x'.repeat(bytes - overhead);
  const body = JSON.stringify(message);
  assert.equal(Buffer.byteLength(body), bytes);
  return body;
}

test('a 1 MiB body reaches the no-key publish guard without a transaction', async () => {
  const result = await request(publishBody(MAX_BODY_BYTES));
  assert.equal(result.status, 200);
  assert.match(result.json.result.content[0].text, /PRIVATE_KEY not configured/);
});

test('a body exceeding 1 MiB is rejected without Content-Length', async () => {
  const result = await request(publishBody(MAX_BODY_BYTES + 1));
  assert.equal(result.status, 413);
});

test('an oversized declared Content-Length is rejected before parsing', async () => {
  const result = await request(JSON.stringify(rpc('tools/list', {})), {
    'content-length': String(MAX_BODY_BYTES + 1),
  });
  assert.equal(result.status, 413);
});

test('Express cannot trust every IPv4 client through an IPv6 trust subnet', () => {
  const sdkRequire = createRequire(require.resolve('@modelcontextprotocol/sdk/server/mcp.js'));
  const expressRequire = createRequire(sdkRequire.resolve('express'));
  const proxyaddr = expressRequire('proxy-addr');
  assert.equal(proxyaddr.compile('::ffff:10.0.0.0/8')('203.0.113.10', 0), false);
  assert.equal(proxyaddr.compile('10.0.0.0/8')('10.1.2.3', 0), true);
  assert.equal(proxyaddr.compile('::ffff:10.0.0.0/104')('10.1.2.3', 0), true);
});
