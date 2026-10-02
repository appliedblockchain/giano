import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { checkDockerfile, externalRefs, parseExceptions, parseImageList } from './check-dockerfiles.mjs';

const D = 'a'.repeat(64);
const DEV = `dhi.io/node:22-alpine3.22-dev@sha256:${D}`;
const RT = `dhi.io/node:22-alpine3.22@sha256:${D}`;
const FOUNDRY = `ghcr.io/foundry-rs/foundry@sha256:${D}`;
const EXC = [{ file: 'svc/Dockerfile', image: 'ghcr.io/foundry-rs/foundry' }];

const rules = (text, file = 'svc/Dockerfile', exceptions = []) =>
  checkDockerfile(text, file, exceptions).map((e) => e.rule);

describe('check-dockerfiles', () => {
  it('passes a compliant two-stage build', () => {
    const text = `FROM ${DEV} AS build
RUN pnpm build
FROM ${RT}
COPY --from=build --chown=65532:65532 /out /app
HEALTHCHECK CMD ["node", "-e", "1"]
CMD ["node", "dist/index.js"]
`;
    assert.deepEqual(rules(text), []);
  });

  it('rejects a community base', () => {
    const errs = checkDockerfile(`FROM node:22-alpine AS build\nFROM ${RT}\n`, 'svc/Dockerfile');
    assert.deepEqual(errs.map((e) => [e.line, e.rule]), [[1, 'dhi-base']]);
  });

  it('rejects a DHI tag without a digest', () => {
    assert.deepEqual(rules(`FROM dhi.io/node:22-alpine3.22-dev AS build\nFROM ${RT}\n`), ['digest-pin']);
  });

  it('rejects a -dev final stage', () => {
    assert.deepEqual(rules(`FROM ${DEV} AS build\nFROM ${DEV}\n`), ['final-runtime']);
  });

  it('rejects a final stage that inherits a -dev stage', () => {
    assert.deepEqual(rules(`FROM ${DEV} AS build\nFROM build\n`), ['final-runtime']);
  });

  it('rejects a runtime variant in a non-final stage', () => {
    assert.deepEqual(rules(`FROM ${RT} AS build\nFROM ${RT}\n`), ['dev-variant']);
  });

  it('rejects RUN in the final stage, across continuations', () => {
    const errs = checkDockerfile(`FROM ${DEV} AS b\nFROM ${RT}\nCOPY a \\\n  b\nRUN chmod +x /x\n`, 'svc/Dockerfile');
    assert.deepEqual(errs.map((e) => [e.line, e.rule]), [[5, 'final-instructions']]);
  });

  it('rejects USER in the final stage', () => {
    assert.deepEqual(rules(`FROM ${DEV} AS b\nFROM ${RT}\nUSER node\n`), ['no-user']);
  });

  it('allows RUN and USER in non-final stages', () => {
    assert.deepEqual(rules(`FROM ${DEV} AS b\nUSER root\nRUN apk add g++\nFROM ${RT}\n`), []);
  });

  it('checks COPY --from of an external image', () => {
    assert.deepEqual(rules(`FROM ${DEV} AS b\nCOPY --from=busybox:latest /bin/sh /bin/sh\nFROM ${RT}\n`), ['dhi-base']);
  });

  it('accepts a recorded exception, digest-pinned', () => {
    assert.deepEqual(rules(`FROM ${FOUNDRY}\nENTRYPOINT ["anvil"]\n`, 'svc/Dockerfile', EXC), []);
    assert.deepEqual(rules(`FROM ${DEV} AS b\nCOPY --from=${FOUNDRY} /f /f\nFROM ${RT}\n`, 'svc/Dockerfile', EXC), []);
  });

  it('still requires the digest on a recorded exception', () => {
    assert.deepEqual(rules('FROM ghcr.io/foundry-rs/foundry:latest\n', 'svc/Dockerfile', EXC), ['digest-pin']);
  });

  it('rejects an exception recorded for a different file', () => {
    assert.deepEqual(rules(`FROM ${FOUNDRY}\n`, 'other/Dockerfile', EXC), ['dhi-base']);
  });

  it('lists only external references', () => {
    const refs = externalRefs(`FROM ${DEV} AS build\nFROM ${RT}\nCOPY --from=build /a /b\nCOPY --from=0 /a /b\n`);
    assert.deepEqual(refs.map((r) => r.ref), [DEV, RT]);
  });

  it('reads the real image list and exceptions block', () => {
    const files = parseImageList(readFileSync(new URL('../.github/workflows/docker.yml', import.meta.url), 'utf8'));
    assert.equal(files.length, 8);
    const exc = parseExceptions(readFileSync(new URL('../docs/abip-compliance.md', import.meta.url), 'utf8'));
    assert.ok(exc.some((e) => e.file === 'services/devnet/Dockerfile'));
  });
});
