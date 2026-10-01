#!/usr/bin/env node
// ABIP-2 Dockerfile policy check (openspec: container-images).
//
//   node scripts/check-dockerfiles.mjs            check every Dockerfile docker.yml publishes
//   node scripts/check-dockerfiles.mjs --refs F   print the dhi.io references in Dockerfile F, one per line
//
// The image list is read from .github/workflows/docker.yml and the exceptions from the
// `abip-2-exceptions` block in docs/abip-compliance.md, so neither is restated here. No
// dependencies and no registry access: it runs on fork PRs too. `--refs` is what docker.yml
// feeds to the base-image signature verification, so the two agree on what a reference is.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const DHI_REF = /^dhi\.io\/[a-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$/;
const DIGEST = /@sha256:[0-9a-f]{64}$/;
// What a final stage may contain. No RUN: the runtime has no shell to run it with, and the
// guide's rule is "COPY, ENV, EXPOSE, USER, CMD/ENTRYPOINT" — minus USER, which ABIP-2 forbids
// switching away from the DHI user, plus metadata that executes nothing.
const FINAL_ALLOWED = new Set([
  'ARG', 'COPY', 'ENV', 'EXPOSE', 'WORKDIR', 'LABEL', 'VOLUME', 'HEALTHCHECK', 'STOPSIGNAL',
  'ENTRYPOINT', 'CMD',
]);

/** Logical Dockerfile instructions: continuations joined, comments and blank lines dropped. */
export function parseInstructions(text) {
  const out = [];
  let buf = '';
  let start = 0;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/\r$/, '');
    if (!buf && /^\s*(#|$)/.test(line)) return;
    if (!buf) start = i + 1;
    // a comment line inside a continuation is skipped, as Docker does
    if (buf && /^\s*#/.test(line)) return;
    if (line.endsWith('\\')) {
      buf += line.slice(0, -1) + ' ';
      return;
    }
    buf += line;
    const m = buf.trim().match(/^(\S+)\s*(.*)$/s);
    out.push({ line: start, op: m[1].toUpperCase(), args: m[2] });
    buf = '';
  });
  return out;
}

/** Stages, each with its base reference and its instructions. */
export function parseStages(text) {
  const stages = [];
  for (const ins of parseInstructions(text)) {
    if (ins.op === 'FROM') {
      const words = ins.args.split(/\s+/).filter((w) => !w.startsWith('--'));
      const asIdx = words.findIndex((w) => w.toUpperCase() === 'AS');
      stages.push({
        base: words[0],
        name: asIdx > 0 ? words[asIdx + 1] : null,
        line: ins.line,
        instructions: [],
      });
    } else if (stages.length) {
      stages[stages.length - 1].instructions.push(ins);
    }
  }
  return stages;
}

function copyFromRef(ins) {
  if (ins.op !== 'COPY' && ins.op !== 'ADD') return null;
  const m = ins.args.match(/(?:^|\s)--from=(\S+)/);
  return m ? m[1] : null;
}

/** Every external image a Dockerfile references (FROM and COPY --from), with its line. */
export function externalRefs(text) {
  const stages = parseStages(text);
  const names = new Set(stages.map((s) => s.name).filter(Boolean));
  const isStage = (ref) => names.has(ref) || /^\d+$/.test(ref);
  const refs = [];
  for (const s of stages) {
    if (!isStage(s.base)) refs.push({ ref: s.base, line: s.line, kind: 'FROM' });
    for (const ins of s.instructions) {
      const from = copyFromRef(ins);
      if (from && !isStage(from)) refs.push({ ref: from, line: ins.line, kind: 'COPY --from' });
    }
  }
  return refs;
}

function tagOf(ref) {
  const noDigest = ref.replace(DIGEST, '');
  const slash = noDigest.lastIndexOf('/');
  const colon = noDigest.indexOf(':', slash);
  return colon === -1 ? '' : noDigest.slice(colon + 1);
}

/** The external image a stage ultimately builds on, following `FROM <stage>` chains. */
function rootBase(stages, idx) {
  const byName = new Map(stages.map((s, i) => [s.name, i]));
  let s = stages[idx];
  const seen = new Set();
  while (byName.has(s.base) || /^\d+$/.test(s.base)) {
    const next = byName.has(s.base) ? byName.get(s.base) : Number(s.base);
    if (seen.has(next)) break;
    seen.add(next);
    s = stages[next];
  }
  return s.base;
}

/**
 * Policy violations for one Dockerfile.
 * @param {string} text Dockerfile contents
 * @param {string} file repo-relative path, used for messages and exception lookup
 * @param {Array<{file: string, image: string}>} exceptions
 */
export function checkDockerfile(text, file, exceptions = []) {
  const errors = [];
  const fail = (line, rule, msg) => errors.push({ file, line, rule, msg });
  const excepted = (ref) =>
    exceptions.some((e) => e.file === file && (ref === e.image || ref.startsWith(`${e.image}@`) || ref.startsWith(`${e.image}:`)));

  const stages = parseStages(text);
  if (stages.length === 0) {
    fail(1, 'no-stage', 'no FROM instruction');
    return errors;
  }

  for (const { ref, line, kind } of externalRefs(text)) {
    if (excepted(ref)) {
      if (!DIGEST.test(ref)) fail(line, 'digest-pin', `${kind} ${ref}: a recorded exception still needs an @sha256 digest`);
      continue;
    }
    if (!ref.startsWith('dhi.io/')) {
      fail(line, 'dhi-base', `${kind} ${ref}: not a Docker Hardened Image and not a recorded exception (docs/abip-compliance.md)`);
    } else if (!DIGEST.test(ref)) {
      fail(line, 'digest-pin', `${kind} ${ref}: tag without an @sha256 digest`);
    } else if (!DHI_REF.test(ref)) {
      fail(line, 'dhi-base', `${kind} ${ref}: expected dhi.io/<repo>:<tag>@sha256:<digest> (keep the tag beside the digest)`);
    }
  }

  const last = stages.length - 1;
  stages.forEach((s, i) => {
    const base = rootBase(stages, i);
    if (!base.startsWith('dhi.io/')) return; // already reported above, or an exception
    const dev = tagOf(base).endsWith('-dev');
    if (i === last && dev) fail(s.line, 'final-runtime', `final stage builds on ${base}: the final stage must use the runtime (non -dev) variant`);
    if (i !== last && !dev) fail(s.line, 'dev-variant', `stage ${s.name ?? i} builds on ${base}: non-final stages must use the -dev variant`);
  });

  for (const ins of stages[last].instructions) {
    if (ins.op === 'USER') fail(ins.line, 'no-user', 'USER in the final stage: run as the DHI-provided non-root user');
    else if (!FINAL_ALLOWED.has(ins.op)) fail(ins.line, 'final-instructions', `${ins.op} in the final stage: it has no shell or package manager to run it`);
  }

  return errors;
}

/** `{file, image}` pairs from the `abip-2-exceptions` fenced block. */
export function parseExceptions(markdown) {
  const m = markdown.match(/```abip-2-exceptions\n([\s\S]*?)```/);
  if (!m) return [];
  return m[1]
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => {
      const [file, image] = l.split(/\s+/);
      return { file, image };
    });
}

/** Dockerfile paths from docker.yml's image list. */
export function parseImageList(workflowYaml) {
  return [...workflowYaml.matchAll(/"dockerfile":\s*"([^"]+)"/g)].map((m) => m[1]);
}

function main(argv) {
  if (argv[0] === '--refs') {
    const file = argv[1];
    if (!file) {
      console.error('usage: check-dockerfiles.mjs --refs <Dockerfile>');
      return 2;
    }
    for (const { ref } of externalRefs(readFileSync(resolve(ROOT, file), 'utf8'))) {
      if (ref.startsWith('dhi.io/')) console.log(ref);
    }
    return 0;
  }

  const files = parseImageList(readFileSync(resolve(ROOT, '.github/workflows/docker.yml'), 'utf8'));
  if (files.length === 0) {
    console.error('no images found in .github/workflows/docker.yml');
    return 1;
  }
  const exceptions = parseExceptions(readFileSync(resolve(ROOT, 'docs/abip-compliance.md'), 'utf8'));
  const errors = files.flatMap((f) => checkDockerfile(readFileSync(resolve(ROOT, f), 'utf8'), f, exceptions));

  for (const e of errors) console.log(`${e.file}:${e.line}: [${e.rule}] ${e.msg}`);
  if (errors.length) {
    console.log(`\n${errors.length} ABIP-2 violation(s) across ${files.length} Dockerfiles`);
    return 1;
  }
  console.log(`ABIP-2: ${files.length} Dockerfiles comply`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
