const assert = require('node:assert/strict');
const { test } = require('node:test');
const vm = require('node:vm');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { patchTracer, patchPackage } = require('./patch-alto-precompile.cjs');

const tracer = `const isAllowedPrecompiled = (address) => {
  const addrHex = toHex(address);
  const addressInt = Number.parseInt(addrHex);
  return addressInt > 0 && addressInt < 10;
}; isAllowedPrecompiled;`;

test('recognizes RIP-7212 while retaining the existing precompile boundaries', () => {
  const allows = vm.runInNewContext(patchTracer(tracer), { toHex: address => address });
  for (const address of [1, 2, 9, 256]) assert.equal(allows(`0x${address.toString(16)}`), true);
  for (const address of [0, 10, 255, 257, 65535]) assert.equal(allows(`0x${address.toString(16)}`), false);
});

test('is idempotent and refuses an unreviewed upstream tracer', () => {
  const patched = patchTracer(tracer);
  assert.equal(patchTracer(patched), patched);
  assert.throws(() => patchTracer('changed upstream tracer'), /review/);
});

test('patches both module formats and refuses incompatible packages before writing', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'alto-precompile-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const metadataFile = path.join(directory, 'package.json');
  fs.writeFileSync(metadataFile, JSON.stringify({ name: '@pimlico/alto', version: '0.0.18' }));
  const files = ['lib', 'esm'].flatMap(format => ['V06', 'V07'].map(version => {
    const file = path.join(directory, format, 'rpc', 'validation', `BundlerCollectorTracer${version}.js`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, tracer);
    return file;
  }));

  // An unexpected tracer must not leave the package partly patched.
  fs.writeFileSync(files[3], 'changed upstream tracer');
  assert.throws(() => patchPackage(directory), /review/);
  for (const file of files.slice(0, 3)) assert.equal(fs.readFileSync(file, 'utf8'), tracer);
  fs.writeFileSync(files[3], tracer);

  fs.writeFileSync(metadataFile, JSON.stringify({ name: '@pimlico/alto', version: '0.0.21' }));
  assert.throws(() => patchPackage(directory), /0\.0\.18/);
  for (const file of files) assert.equal(fs.readFileSync(file, 'utf8'), tracer);

  fs.writeFileSync(metadataFile, JSON.stringify({ name: '@pimlico/alto', version: '0.0.18' }));
  patchPackage(directory);
  patchPackage(directory);
  for (const file of files) assert.equal(fs.readFileSync(file, 'utf8'), patchTracer(tracer));
});
