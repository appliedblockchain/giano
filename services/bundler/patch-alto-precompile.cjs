const fs = require('node:fs');
const path = require('node:path');

// Alto 0.0.18's ERC-4337 tracer predates RIP-7212 and only recognizes precompiles 1–9.
// Base Sepolia's stateless P-256 verifier at 0x100 must also be excluded from the
// zero-bytecode check. Keep all other validation rules, including safe mode, intact.
const original = 'return addressInt > 0 && addressInt < 10;';
const replacement = 'return (addressInt > 0 && addressInt < 10) || addressInt === 256;';

function patchTracer(source) {
  if (source.includes(replacement) && !source.includes(original)) return source;
  if (source.split(original).length !== 2) {
    throw new Error('Alto precompile tracer changed; review the RIP-7212 patch before upgrading');
  }
  return source.replace(original, replacement);
}

function patchPackage(directory) {
  const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  if (metadata.name !== '@pimlico/alto' || metadata.version !== '0.0.18') {
    throw new Error('The RIP-7212 patch is reviewed only for @pimlico/alto 0.0.18');
  }
  const patches = ['lib', 'esm'].flatMap(format => ['V06', 'V07'].map(version => {
    const file = path.join(directory, format, 'rpc', 'validation', `BundlerCollectorTracer${version}.js`);
    return { file, source: patchTracer(fs.readFileSync(file, 'utf8')) };
  }));
  for (const { file, source } of patches) fs.writeFileSync(file, source);
}

module.exports = { patchTracer, patchPackage };
if (require.main === module) patchPackage(process.argv[2]);
