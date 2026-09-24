import { z } from 'zod';
import { ADDRESS_RE, canonicalSignature, functionSelector, isSelector } from './signature';
import type { Mapping, ValidationIssue, ValidationResult } from './types';

/**
 * Validation of an ERC-7730 descriptor as a Giano mapping.
 *
 * This is deliberately stricter than the ERC-7730 schema in three places, all so that the
 * library can stay offline and deterministic: the ABI must be inline, `includes` is refused,
 * and every function key must resolve to a function in that ABI. It is looser everywhere else —
 * unknown keys pass through — so a descriptor copied from the public registry (with its ABI
 * inlined) validates unchanged.
 */

const FIELD_FORMATS = [
  'raw',
  'amount',
  'tokenAmount',
  'nftName',
  'date',
  'duration',
  'unit',
  'enum',
  'chainId',
  'addressName',
  'tokenTicker',
  'calldata',
  'interoperableAddressName',
] as const;

const addressSchema = z.string().regex(ADDRESS_RE, 'must be a 0x-prefixed 20-byte hex address');

const deploymentSchema = z.object({
  chainId: z.number().int().positive('chainId must be a positive integer'),
  address: addressSchema,
});

const abiParamSchema: z.ZodType<AbiParam> = z.lazy(() =>
  z
    .object({
      name: z.string().optional(),
      type: z.string(),
      components: z.array(abiParamSchema).optional(),
    })
    .passthrough(),
);

const abiItemSchema = z
  .object({
    type: z.string(),
    name: z.string().optional(),
    inputs: z.array(abiParamSchema).optional(),
  })
  .passthrough();

const fieldSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z
      .object({
        path: z.string().min(1).optional(),
        $ref: z.string().optional(),
        label: z.string().optional(),
        format: z.enum(FIELD_FORMATS).optional(),
        params: z.record(z.unknown()).optional(),
        value: z.unknown().optional(),
        visible: z.unknown().optional(),
        separator: z.string().optional(),
      })
      .passthrough()
      .refine((f) => f.path !== undefined || f.$ref !== undefined, {
        message: 'a field needs a path (or a $ref to a definition)',
        path: ['path'],
      }),
    z
      .object({
        path: z.string().optional(),
        label: z.string().optional(),
        fields: z.array(fieldSchema),
        iteration: z.enum(['sequential', 'bundled']).optional(),
      })
      .passthrough(),
  ]),
);

const formatSpecSchema = z
  .object({
    $id: z.string().optional(),
    intent: z.union([z.string().min(1), z.record(z.string())]).optional(),
    interpolatedIntent: z.string().min(1).optional(),
    fields: z.array(fieldSchema).optional(),
  })
  .passthrough()
  .refine((f) => f.intent !== undefined || f.interpolatedIntent !== undefined, {
    message: 'a format needs an intent or an interpolatedIntent — without one there is nothing readable to show',
    path: ['intent'],
  });

const descriptorSchema = z
  .object({
    $schema: z.string().optional(),
    includes: z.undefined({ invalid_type_error: 'includes is not supported: inline the included descriptor' }),
    context: z.object({
      contract: z
        .object({
          deployments: z.array(deploymentSchema).min(1, 'at least one deployment binding is required'),
          abi: z.array(abiItemSchema, { invalid_type_error: 'abi must be inline (an array of ABI items), not a URL' }),
        })
        .passthrough(),
    }),
    metadata: z.record(z.unknown()).optional(),
    display: z.object({
      definitions: z.record(z.unknown()).optional(),
      formats: z.record(formatSpecSchema).refine((f) => Object.keys(f).length > 0, 'at least one function format is required'),
    }),
  })
  .passthrough();

type AbiParam = { name?: string; type: string; components?: AbiParam[] };
type AbiFunction = { type: string; name?: string; inputs?: AbiParam[] };

function abiSignature(fn: AbiFunction): string {
  const params = (fn.inputs ?? []).map(paramType).join(',');
  return `${fn.name}(${params})`;
}

function paramType(p: AbiParam): string {
  if (p.type.startsWith('tuple')) {
    const suffix = p.type.slice('tuple'.length);
    return `(${(p.components ?? []).map(paramType).join(',')})${suffix}`;
  }
  return p.type;
}

/** The first segment of a field path, without `#.` prefix, array index or nested member. */
function rootName(path: string): string {
  const stripped = path.startsWith('#.') ? path.slice(2) : path;
  return stripped.split(/[.[]/)[0] ?? '';
}

function collectFieldPaths(fields: unknown, prefix: string, out: Array<{ path: string; at: string }>): void {
  if (!Array.isArray(fields)) return;
  fields.forEach((field, index) => {
    const at = `${prefix}[${index}]`;
    if (!field || typeof field !== 'object') return;
    const f = field as { path?: string; fields?: unknown };
    if (typeof f.path === 'string') out.push({ path: f.path, at: `${at}.path` });
    if (f.fields) collectFieldPaths(f.fields, `${at}.fields`, out);
  });
}

/**
 * Validates a mapping. Never throws; unparseable input is an issue at the root path.
 * Cross-checks beyond the shape: each format key must be a selector or a signature and must
 * resolve to a function in the inline ABI; each calldata field path must name one of that
 * function's inputs (container paths `@.…` and metadata paths `$.…` are accepted as-is).
 */
export function validateMapping(input: unknown): ValidationResult {
  const parsed = descriptorSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map((issue) => ({ path: issue.path.map(String).join('.') || '(root)', message: issue.message })),
    };
  }
  const descriptor = parsed.data;
  const issues: ValidationIssue[] = [];

  const functions = (descriptor.context.contract.abi as AbiFunction[]).filter((item) => item.type === 'function' && item.name);
  const bySelector = new Map<string, AbiFunction>();
  for (const fn of functions) bySelector.set(functionSelector(abiSignature(fn)), fn);

  for (const [key, spec] of Object.entries(descriptor.display.formats)) {
    const at = `display.formats.${key}`;
    let selector: string;
    try {
      selector = functionSelector(key);
    } catch {
      issues.push({ path: at, message: `not a selector or a function signature: ${key}. Expected e.g. "transfer(address to, uint256 value)" or "0xa9059cbb"` });
      continue;
    }
    const fn = bySelector.get(selector);
    if (!fn) {
      issues.push({ path: at, message: `no function in the ABI matches ${isSelector(key) ? key : `${canonicalSignature(key)} (${selector})`}` });
      continue;
    }
    const inputNames = new Set((fn.inputs ?? []).map((p, i) => p.name || String(i)));
    const paths: Array<{ path: string; at: string }> = [];
    collectFieldPaths(spec.fields, `${at}.fields`, paths);
    for (const { path, at: pathAt } of paths) {
      if (path.startsWith('@.') || path.startsWith('$.')) continue;
      const root = rootName(path);
      if (!inputNames.has(root)) {
        issues.push({ path: pathAt, message: `"${path}" does not name an input of ${abiSignature(fn)} (inputs: ${[...inputNames].join(', ') || 'none'})` });
      }
    }
  }

  return issues.length === 0 ? { ok: true, issues: [] } : { ok: false, issues };
}

/** The `(chainId, address)` pairs a mapping binds, addresses lowercased. Empty when malformed. */
export function deploymentsOf(mapping: Mapping): Array<{ chainId: number; address: string }> {
  const list = mapping.context?.contract?.deployments;
  if (!Array.isArray(list)) return [];
  return list
    .filter((d) => typeof d?.chainId === 'number' && typeof d?.address === 'string' && ADDRESS_RE.test(d.address))
    .map((d) => ({ chainId: d.chainId as number, address: (d.address as string).toLowerCase() }));
}

/** True when the mapping binds this chain and contract. */
export function mappingCovers(mapping: Mapping, chainId: number, contract: string): boolean {
  const target = contract.toLowerCase();
  return deploymentsOf(mapping).some((d) => d.chainId === chainId && d.address === target);
}

/** Selectors of every function format in a mapping; keys that do not parse are skipped. */
export function selectorsOf(mapping: Mapping): Map<string, string> {
  const out = new Map<string, string>();
  const formats = mapping.display?.formats;
  if (!formats) return out;
  for (const key of Object.keys(formats)) {
    try {
      out.set(functionSelector(key), key);
    } catch {
      // an unparseable key never matches anything
    }
  }
  return out;
}
