/**
 * Snapshots the paymaster's storage layout to `storage-layout/GianoPaymaster.json`, and with
 * `--check` fails on any drift.
 *
 * The paymaster holds customer funds, and a mis-ordered storage slot silently re-attributes them:
 * a tenant's balance becomes another tenant's, or the treasury, and there is no recovery once real
 * money is attributed by it. ERC-7201 namespacing makes *appending* to the struct safe by
 * construction, but it does not stop a reordering, a type narrowing, or a field removal — and
 * reviewing that by eye is explicitly not good enough.
 *
 * So the layout is committed, and any change has to show up as a diff someone acknowledges in a
 * pull request. Appending a field produces a small additive diff, which is fine. Anything else
 * should stop the reviewer cold.
 *
 * Usage:  pnpm storage         (write)
 *         pnpm storage:check   (verify)
 */
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(dir, '..');
const outDir = path.join(root, 'storage-layout');
const outPath = path.join(outDir, 'GianoPaymaster.json');

/*
 * `PaymasterStorageProbe`, not `GianoPaymaster`.
 *
 * The paymaster addresses its ERC-7201 namespace from assembly, so the compiler reports no storage
 * layout for it whatsoever — a snapshot of the contract itself would be an empty file that passes
 * forever. The probe declares the same struct as an ordinary state variable purely so the layout
 * that actually matters becomes inspectable.
 */
const raw = execFileSync('forge', ['inspect', 'PaymasterStorageProbe', 'storageLayout', '--json'], { cwd: root, encoding: 'utf8' });
const layout = JSON.parse(raw);

if ((layout.storage ?? []).length === 0) {
  console.error(
    'forge reported an empty storage layout for PaymasterStorageProbe.\n' +
      'That almost certainly means the probe no longer references GianoPaymaster.PaymasterStorage —\n' +
      'in which case this check would silently pass forever. Fix the probe rather than the snapshot.\n',
  );
  process.exit(1);
}

/**
 * Only the shape matters, and it has to be *stable*.
 *
 * Solidity embeds AST node ids in type keys (`t_struct(Tenant)10886_storage`) and reports an `astId`
 * per entry. Both renumber whenever anything above them in the source moves, so keeping them would
 * make this file churn on every unrelated edit — and a snapshot nobody reads the diff of protects
 * nothing. Stripping them leaves exactly the property that must not change: which field sits in
 * which slot, at which offset, with which type.
 */
const stripAstIds = (value) => value.replace(/\)\d+/g, ')');
const normalised = {
  storage: (layout.storage ?? []).map((entry) => ({
    label: entry.label,
    slot: entry.slot,
    offset: entry.offset,
    type: stripAstIds(entry.type),
  })),
  types: Object.fromEntries(
    Object.entries(layout.types ?? {})
      .sort(([a], [b]) => stripAstIds(a).localeCompare(stripAstIds(b)))
      .map(([key, value]) => [
        stripAstIds(key),
        {
          label: value.label,
          numberOfBytes: value.numberOfBytes,
          encoding: value.encoding,
          ...(value.key ? { key: stripAstIds(value.key) } : {}),
          ...(value.value ? { value: stripAstIds(value.value) } : {}),
          ...(value.members
            ? {
                members: value.members.map((m) => ({
                  label: m.label,
                  slot: m.slot,
                  offset: m.offset,
                  type: stripAstIds(m.type),
                })),
              }
            : {}),
        },
      ]),
  ),
};

const serialised = `${JSON.stringify(normalised, null, 2)}\n`;

if (process.argv.includes('--check')) {
  const committed = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : '';
  if (committed !== serialised) {
    console.error(
      'The paymaster storage layout has changed.\n\n' +
        'If this is an intentional, append-only addition, run `pnpm storage` and commit the diff —\n' +
        'and say so in the pull request. If it reorders, removes or narrows an existing field, it is\n' +
        'not upgrade-safe: it would silently re-attribute funds already recorded in those slots.\n',
    );
    process.exit(1);
  }
  console.log('storage-layout/GianoPaymaster.json is up to date');
} else {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outPath, serialised);
  console.log(`Wrote ${path.relative(process.cwd(), outPath)}`);
}
