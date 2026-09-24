/**
 * The one module that touches `@ethereum-sourcify/clear-signing`.
 *
 * Spike outcome (2026-09-24, v0.2.2, design D2): passes the bar. `format()` accepts an
 * in-memory `DescriptorResolver` and performs no network access on that path; missing
 * descriptors, unmatched selectors and undecodable calldata come back as distinct warning
 * codes with a raw fallback; native amounts take the currency from `resolveChainInfo`; token
 * amounts take symbol and decimals from `resolveToken`. The engine ships no validator, so
 * validation is Giano's (`validate.ts`). Nothing outside this file may import the engine, so
 * that swapping it — or replacing it with an in-house ERC-7730 subset — touches one module.
 */
import { format, isFieldGroup, type Descriptor, type DisplayField, type DisplayModel } from '@ethereum-sourcify/clear-signing';
import { checksumAddress, functionSelector, isAddress, isSelector, shortAddress } from './signature';
import type { DescriptionField, DescriptionWarning, NativeCurrency, TokenResolver } from './types';

export type EngineInput = {
  chainId: number;
  to: string;
  data: string;
  value: bigint;
  descriptor: Descriptor;
  nativeCurrency: NativeCurrency;
  resolveToken?: TokenResolver;
};

export type EngineResult =
  | {
      ok: true;
      intent: string;
      fields: DescriptionField[];
      metadata?: { contractName?: string; owner?: string };
      warnings: DescriptionWarning[];
    }
  | { ok: false; reason: 'no-mapping' | 'decode-failed'; message: string };

const DECODE_CODES = new Set(['INVALID_CALLDATA_HEX', 'CALLDATA_TOO_SHORT', 'CALLDATA_DECODE_ERROR', 'ARGUMENT_TYPE_MISMATCH']);
const NO_MAPPING_CODES = new Set(['NO_DESCRIPTOR', 'NO_FORMAT_MATCH', 'DEPLOYMENT_MISMATCH', 'DESCRIPTOR_FETCH_ERROR', 'INVALID_DESCRIPTOR']);

/** Formats one call against one descriptor already known to bind `(chainId, to)`. */
export async function formatCall(input: EngineInput): Promise<EngineResult> {
  const address = input.to.toLowerCase();
  const path = 'mapping.json';
  const descriptor = withSignatureKeys(input.descriptor);
  const model: DisplayModel = await format(
    { chainId: input.chainId, to: address, data: input.data, value: input.value },
    {
      descriptorResolverOptions: {
        type: 'custom',
        resolver: {
          index: { calldataIndex: { [`eip155:${input.chainId}:${address}`]: path }, typedDataIndex: {} },
          fetchDescriptor: async (requested) => {
            if (requested !== path) throw new Error(`descriptor includes are not supported (${requested})`);
            return descriptor;
          },
        },
      },
      externalDataProvider: {
        // Addresses are shown short and checksummed; the full value travels in `rawAddress`.
        resolveLocalName: async (addr) => (isAddress(addr) ? { name: shortAddress(addr), typeMatch: true } : null),
        resolveToken: async (chainId, token) => {
          if (!input.resolveToken) return null;
          try {
            const info = await input.resolveToken(chainId, token);
            return info ? { name: info.name ?? info.symbol, symbol: info.symbol, decimals: info.decimals } : null;
          } catch {
            return null;
          }
        },
        resolveChainInfo: async () => ({
          name: `chain ${input.chainId}`,
          nativeCurrency: { name: input.nativeCurrency.name ?? input.nativeCurrency.symbol, symbol: input.nativeCurrency.symbol, decimals: input.nativeCurrency.decimals },
        }),
      },
    },
  );

  const codes = (model.warnings ?? []).map((w) => w.code);
  if (model.rawCalldataFallback || (!model.intent && !model.interpolatedIntent)) {
    const message = model.warnings?.map((w) => w.message).join('; ') || 'the engine produced no description';
    if (codes.some((c) => DECODE_CODES.has(c))) return { ok: false, reason: 'decode-failed', message };
    if (codes.some((c) => NO_MAPPING_CODES.has(c))) return { ok: false, reason: 'no-mapping', message };
    return { ok: false, reason: 'decode-failed', message };
  }

  const warnings: DescriptionWarning[] = [];
  const fields: DescriptionField[] = [];
  for (const item of model.fields ?? []) {
    const leaves: DisplayField[] = isFieldGroup(item) ? item.fields : [item];
    for (const leaf of leaves) fields.push(toField(leaf, warnings));
  }

  for (const warning of model.warnings ?? []) {
    if (warning.code === 'INTERPOLATION_ERROR') warnings.push({ code: 'interpolation-failed', message: warning.message });
    else warnings.push({ code: 'engine', message: `${warning.code}: ${warning.message}` });
  }

  const intent = model.interpolatedIntent ?? intentText(model.intent!);
  return { ok: true, intent, fields, metadata: pickMetadata(model), warnings };
}

type AbiInput = { name?: string; type: string; components?: AbiInput[] };
type AbiFn = { type: string; name?: string; inputs?: AbiInput[] };

/**
 * The engine decodes calldata from the *types in the format key*, so it only understands
 * signature keys. ERC-7730 also allows a raw selector as the key; those are rewritten here to
 * the signature of the ABI function with that selector, parameter names included, so a
 * selector-keyed format can still address its fields by name.
 */
function withSignatureKeys(descriptor: Descriptor): Descriptor {
  const formats = descriptor.display?.formats;
  if (!formats || !Object.keys(formats).some(isSelector)) return descriptor;
  const abi = (descriptor.context?.contract as { abi?: AbiFn[] } | undefined)?.abi ?? [];
  const bySelector = new Map<string, string>();
  for (const fn of abi) {
    if (fn.type !== 'function' || !fn.name) continue;
    const typed = `${fn.name}(${(fn.inputs ?? []).map(typeOf).join(',')})`;
    const named = `${fn.name}(${(fn.inputs ?? []).map((p, i) => `${typeOf(p)} ${p.name || `arg${i}`}`).join(', ')})`;
    try {
      bySelector.set(functionSelector(typed), named);
    } catch {
      // an ABI item the selector helper cannot canonicalise is simply not addressable by selector
    }
  }
  const rewritten: Record<string, unknown> = {};
  for (const [key, spec] of Object.entries(formats)) {
    rewritten[isSelector(key) ? (bySelector.get(key.toLowerCase()) ?? key) : key] = spec;
  }
  return { ...descriptor, display: { ...descriptor.display, formats: rewritten as Descriptor['display'] extends { formats?: infer F } ? F : never } };
}

function typeOf(p: AbiInput): string {
  if (p.type.startsWith('tuple')) return `(${(p.components ?? []).map(typeOf).join(',')})${p.type.slice('tuple'.length)}`;
  return p.type;
}

function intentText(intent: string | Record<string, string>): string {
  if (typeof intent === 'string') return intent;
  return Object.entries(intent)
    .map(([k, v]) => `${k}: ${v}`)
    .join(' · ');
}

function pickMetadata(model: DisplayModel): { contractName?: string; owner?: string } | undefined {
  const { contractName, owner } = model.metadata ?? {};
  if (!contractName && !owner) return undefined;
  return { ...(contractName ? { contractName } : {}), ...(owner ? { owner } : {}) };
}

function toField(leaf: DisplayField, warnings: DescriptionWarning[]): DescriptionField {
  const label = leaf.separator ? `${leaf.separator} ${leaf.label}` : leaf.label;

  if (leaf.fieldType === 'address') {
    const full = leaf.rawAddress && isAddress(leaf.rawAddress) ? checksumAddress(leaf.rawAddress) : isAddress(leaf.value) ? checksumAddress(leaf.value) : undefined;
    return { label, value: full ? shortAddress(full) : leaf.value, kind: 'address', ...(full ? { address: full } : {}) };
  }

  if (leaf.format === 'tokenAmount') {
    const token = leaf.tokenAddress && isAddress(leaf.tokenAddress) ? checksumAddress(leaf.tokenAddress) : undefined;
    if (leaf.warning?.code === 'UNKNOWN_TOKEN') {
      warnings.push({
        code: 'token-unresolved',
        message: `the token at ${token ?? leaf.tokenAddress ?? 'an unknown address'} could not be resolved; "${label}" is shown unscaled`,
      });
      return { label, value: token ? `${leaf.value} (token ${shortAddress(token)})` : leaf.value, kind: 'token-amount', ...(token ? { address: token } : {}) };
    }
    return { label, value: leaf.value, kind: 'token-amount', ...(token ? { address: token } : {}) };
  }

  if (leaf.format === 'amount') return { label, value: leaf.value, kind: 'amount' };

  if (leaf.warning && leaf.warning.code !== 'UNKNOWN_ADDRESS') {
    warnings.push({ code: 'engine', message: `${label}: ${leaf.warning.message}` });
  }
  return { label, value: leaf.value, kind: 'text' };
}
