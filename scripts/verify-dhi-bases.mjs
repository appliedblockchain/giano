#!/usr/bin/env node
// Verify Docker's signature on every Docker Hardened Image a Dockerfile builds on, before building it
// (ABIP-2 migration guide: "the CI/CD pipeline must also verify the signature of any pulled hardened
// base image"; openspec container-images, "Base image signatures are verified before building").
//
//   node scripts/verify-dhi-bases.mjs <Dockerfile>...
//
// Needs cosign on PATH and a `docker login dhi.io`. The references are the ones the policy check
// parses (check-dockerfiles.mjs), so what is verified is exactly what is pinned. DHI signs the
// multi-arch INDEX and attaches the signature as an OCI 1.1 referrer — hence --experimental-oci11 —
// and does not write it to the public Rekor log, hence verification by Docker's published key with
// the transparency-log check off, as Docker documents.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { externalRefs } from './check-dockerfiles.mjs';

export const DHI_KEY = 'https://registry.scout.docker.com/keyring/dhi/latest.pub';

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error('usage: verify-dhi-bases.mjs <Dockerfile>...');
  process.exit(2);
}

const refs = [
  ...new Set(
    files.flatMap((f) => externalRefs(readFileSync(resolve(f), 'utf8')).map((r) => r.ref)).filter((r) => r.startsWith('dhi.io/')),
  ),
];

let failed = 0;
for (const ref of refs) {
  const res = spawnSync(
    'cosign',
    ['verify', ref, '--key', DHI_KEY, '--insecure-ignore-tlog=true', '--experimental-oci11', '--output', 'json'],
    { encoding: 'utf8' },
  );
  if (res.error) throw res.error;
  if (res.status !== 0) {
    failed++;
    console.log(`::error::${ref}: Docker's DHI signature did not verify\n${res.stderr}`);
    continue;
  }
  // The signed claim must name the digest that is pinned, not merely some image in the repository.
  const digest = ref.slice(ref.indexOf('@') + 1);
  const claims = JSON.parse(res.stdout);
  const ok = claims.some((c) => c?.critical?.image?.['docker-manifest-digest'] === digest);
  if (!ok) {
    failed++;
    console.log(`::error::${ref}: a signature verified, but none signs ${digest}`);
    continue;
  }
  console.log(`verified ${ref}`);
}

if (failed) {
  console.log(`${failed} of ${refs.length} DHI base reference(s) failed verification`);
  process.exit(1);
}
console.log(`${refs.length} DHI base reference(s) verified`);
