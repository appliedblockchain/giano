import { bindBuiltin, builtinFor } from './builtins';
import { formatCall } from './engine';
import { checksumAddress, formatUnits, HEX_RE, isAddress, shortAddress, toBigInt } from './signature';
import type {
  DescribeOptions,
  DescribedTransaction,
  DescriptionWarning,
  Mapping,
  RawTransaction,
  TransactionDescription,
  TransactionInput,
  UnknownReason,
} from './types';
import { mappingCovers, selectorsOf } from './validate';

const DEFAULT_NATIVE = { symbol: 'ETH', decimals: 18 };

/**
 * Describes a transaction from a mapping set. Never throws and never guesses: a call that no
 * mapping explains is returned as `unknown` with its raw fields, not as a pretty-printed ABI.
 */
export async function describeTransaction(tx: TransactionInput, options: DescribeOptions = {}): Promise<TransactionDescription> {
  const nativeCurrency = options.nativeCurrency ?? DEFAULT_NATIVE;
  const useBuiltins = options.builtins ?? true;

  const raw = rawOf(tx);
  const unknown = (reason: UnknownReason, selector: string | null, contract: string | null, warnings: DescriptionWarning[] = []) =>
    ({ kind: 'unknown', reason, selector, contract, warnings, raw }) as const;

  // ── Input normalisation: anything malformed is `decode-failed`, never a throw ──────────
  if (tx.to === undefined || tx.to === null || tx.to === '') return unknown('contract-creation', null, null);
  if (!isAddress(tx.to)) return unknown('decode-failed', null, null, [{ code: 'engine', message: `"to" is not an address: ${String(tx.to)}` }]);
  const contract = checksumAddress(tx.to);

  let value: bigint;
  try {
    value = tx.value === undefined || tx.value === null || tx.value === '' ? 0n : toBigInt(tx.value);
  } catch (error) {
    return unknown('decode-failed', null, contract, [{ code: 'engine', message: (error as Error).message }]);
  }

  const data = typeof tx.data === 'string' && tx.data !== '' ? tx.data : '0x';
  if (typeof tx.data !== 'string' && tx.data !== undefined && tx.data !== null) {
    return unknown('decode-failed', null, contract, [{ code: 'engine', message: '"data" is not a hex string' }]);
  }
  if (!HEX_RE.test(data)) return unknown('decode-failed', null, contract, [{ code: 'engine', message: '"data" is not valid hex' }]);

  // ── Native transfer: no calldata, no mapping needed ───────────────────────────────────
  if (data === '0x') {
    const amount = `${formatUnits(value, nativeCurrency.decimals)} ${nativeCurrency.symbol}`;
    return {
      kind: 'described',
      intent: `Send ${amount} to ${shortAddress(contract)}`,
      fields: [
        { label: 'Amount', value: amount, kind: 'amount' },
        { label: 'Recipient', value: shortAddress(contract), kind: 'address', address: contract },
      ],
      source: 'native',
      contract,
      functionSignature: null,
      selector: null,
      warnings: [],
      raw,
    };
  }

  if (data.length < 10) return unknown('decode-failed', null, contract, [{ code: 'engine', message: 'calldata is shorter than a 4-byte selector' }]);
  const selector = data.slice(0, 10).toLowerCase();

  // ── Selection: caller mapping for (chain, to) with this selector, then built-in ────────
  let descriptor: Mapping | undefined;
  let source: 'mapping' | 'generic' | undefined;
  let functionKey: string | undefined;

  for (const mapping of options.mappings ?? []) {
    if (!mappingCovers(mapping, tx.chainId, contract)) continue;
    const key = selectorsOf(mapping).get(selector);
    if (key) {
      descriptor = mapping;
      source = 'mapping';
      functionKey = key;
      break;
    }
  }

  if (!descriptor && useBuiltins) {
    const template = builtinFor(selector);
    if (template) {
      descriptor = bindBuiltin(template, tx.chainId, contract);
      source = 'generic';
      functionKey = selectorsOf(descriptor).get(selector);
    }
  }

  if (!descriptor || !source) return unknown('no-mapping', selector, contract);

  // ── Formatting ───────────────────────────────────────────────────────────────────────
  let result;
  try {
    result = await formatCall({ chainId: tx.chainId, to: contract, data, value, descriptor, nativeCurrency, resolveToken: options.resolveToken });
  } catch (error) {
    return unknown('decode-failed', selector, contract, [{ code: 'engine', message: (error as Error)?.message ?? 'formatting failed' }]);
  }
  if (!result.ok) return unknown(result.reason, selector, contract, [{ code: 'engine', message: result.message }]);

  const warnings = [...result.warnings];
  if (source === 'generic') {
    warnings.unshift({
      code: 'generic-interface',
      message: `described from the generic ${descriptor.metadata?.contractName ?? 'token'} mapping by selector; this contract has not been confirmed to implement that interface`,
    });
  }

  const fields = [...result.fields];
  if (value > 0n && !mentionsContainerValue(descriptor, functionKey)) {
    fields.push({ label: 'Value', value: `${formatUnits(value, nativeCurrency.decimals)} ${nativeCurrency.symbol}`, kind: 'amount' });
  }

  const described: DescribedTransaction = {
    kind: 'described',
    intent: result.intent,
    fields,
    source,
    contract,
    functionSignature: functionKey ?? selector,
    selector,
    ...(result.metadata ? { metadata: result.metadata } : {}),
    warnings,
    raw,
  };
  return described;
}

/** True when the matched format already displays the call's native value (`@.value`). */
function mentionsContainerValue(descriptor: Mapping, functionKey: string | undefined): boolean {
  if (!functionKey) return false;
  const spec = descriptor.display?.formats?.[functionKey];
  const stack: unknown[] = [...(spec?.fields ?? [])];
  while (stack.length) {
    const field = stack.pop() as { path?: string; fields?: unknown[] } | undefined;
    if (!field) continue;
    if (field.path === '@.value') return true;
    if (Array.isArray(field.fields)) stack.push(...field.fields);
  }
  return false;
}

function rawOf(tx: TransactionInput): RawTransaction {
  let value = '0x0';
  try {
    value = `0x${toBigInt(tx.value ?? 0).toString(16)}`;
  } catch {
    value = String(tx.value);
  }
  return {
    to: typeof tx.to === 'string' && tx.to !== '' ? tx.to : null,
    value,
    data: typeof tx.data === 'string' && tx.data !== '' ? tx.data : '0x',
  };
}
