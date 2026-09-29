import { describe, expect, it } from 'vitest';
import { describeTransaction, type DescribedTransaction, type UnknownTransaction } from '../src/index';
import {
  approveData,
  CHAIN,
  OTHER,
  RECIPIENT,
  resolveUsdc,
  safeTransferFromData,
  SEL,
  setApprovalForAllData,
  SPENDER,
  transferData,
  transferFromData,
  USDC,
  usdcMapping,
} from './fixtures';

const described = (r: Awaited<ReturnType<typeof describeTransaction>>): DescribedTransaction => {
  expect(r.kind).toBe('described');
  return r as DescribedTransaction;
};
const unknown = (r: Awaited<ReturnType<typeof describeTransaction>>): UnknownTransaction => {
  expect(r.kind).toBe('unknown');
  return r as UnknownTransaction;
};

describe('caller-supplied mappings', () => {
  it('describes a tenant-mapped call with scaled token amount and short recipient', async () => {
    const r = described(
      await describeTransaction(
        { chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 10_500_000n) },
        { mappings: [usdcMapping()], resolveToken: resolveUsdc },
      ),
    );
    expect(r.intent).toBe('Send 10.5 USDC to 0x2222…2222');
    expect(r.fields).toEqual([
      { label: 'Amount', value: '10.5 USDC', kind: 'token-amount', address: '0x1111111111111111111111111111111111111111' },
      { label: 'Recipient', value: '0x2222…2222', kind: 'address', address: '0x2222222222222222222222222222222222222222' },
    ]);
    expect(r.source).toBe('mapping');
    expect(r.selector).toBe(SEL.transfer);
    expect(r.functionSignature).toBe('transfer(address to, uint256 value)');
    expect(r.metadata).toEqual({ contractName: 'USD Coin', owner: 'Acme' });
    expect(r.warnings).toEqual([]);
  });

  it('covers every call of the same kind with one mapping', async () => {
    const opts = { mappings: [usdcMapping()], resolveToken: resolveUsdc };
    const a = described(await describeTransaction({ chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 1_000_000n) }, opts));
    const b = described(await describeTransaction({ chainId: CHAIN, to: USDC, data: transferData(OTHER, 25n) }, opts));
    expect(a.intent).toBe('Send 1 USDC to 0x2222…2222');
    expect(b.intent).toBe('Send 0.000025 USDC to 0x4444…4444');
    expect(a.functionSignature).toBe(b.functionSignature);
  });

  it('does not apply a mapping bound to another chain', async () => {
    const r = await describeTransaction(
      { chainId: 8453, to: USDC, data: transferData(RECIPIENT, 1n) },
      { mappings: [usdcMapping()], builtins: false, resolveToken: resolveUsdc },
    );
    expect(unknown(r).reason).toBe('no-mapping');
  });

  it('adds a native value field when a described call carries value', async () => {
    const r = described(
      await describeTransaction(
        { chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 1n), value: '0x' + (1_500_000_000_000_000_000n).toString(16) },
        { mappings: [usdcMapping()], resolveToken: resolveUsdc, nativeCurrency: { symbol: 'MATIC', decimals: 18 } },
      ),
    );
    expect(r.fields.at(-1)).toEqual({ label: 'Value', value: '1.5 MATIC', kind: 'amount' });
  });

  it('does not duplicate a value field the mapping already shows', async () => {
    const payable = usdcMapping({
      context: {
        contract: {
          deployments: [{ chainId: CHAIN, address: USDC }],
          abi: [{ type: 'function', name: 'deposit', stateMutability: 'payable', inputs: [], outputs: [] }],
        },
      },
      display: {
        formats: {
          'deposit()': { intent: 'Deposit', interpolatedIntent: 'Deposit {@.value}', fields: [{ path: '@.value', label: 'Deposit', format: 'amount' }] },
        },
      },
    });
    const r = described(
      await describeTransaction({ chainId: CHAIN, to: USDC, data: SEL.deposit, value: 2_000_000_000_000_000_000n }, { mappings: [payable] }),
    );
    expect(r.fields.filter((f) => f.kind === 'amount')).toHaveLength(1);
    expect(r.fields[0]).toEqual({ label: 'Deposit', value: '2 ETH', kind: 'amount' });
  });

  it('prefers the caller mapping over a built-in for the same selector', async () => {
    const r = described(
      await describeTransaction({ chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 1n) }, { mappings: [usdcMapping()], resolveToken: resolveUsdc }),
    );
    expect(r.source).toBe('mapping');
    expect(r.warnings.some((w) => w.code === 'generic-interface')).toBe(false);
  });

  it('uses the mapping only when a selector-keyed format matches', async () => {
    const selectorKeyed = usdcMapping({
      display: {
        formats: {
          '0xa9059cbb': {
            intent: 'Send USDC',
            interpolatedIntent: 'Send {value} to {to}',
            fields: [
              { path: 'value', label: 'Amount', format: 'tokenAmount', params: { tokenPath: '@.to' } },
              { path: 'to', label: 'Recipient', format: 'addressName' },
            ],
          },
        },
      },
    });
    const r = described(
      await describeTransaction({ chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 10_500_000n) }, { mappings: [selectorKeyed], resolveToken: resolveUsdc }),
    );
    expect(r.intent).toBe('Send 10.5 USDC to 0x2222…2222');
    expect(r.functionSignature).toBe('0xa9059cbb');
  });
});

describe('built-in generic mappings', () => {
  it('describes an approve on an unmapped contract as generic with a warning', async () => {
    const r = described(await describeTransaction({ chainId: CHAIN, to: OTHER, data: approveData(SPENDER, 5_000_000n) }, { resolveToken: resolveUsdc }));
    expect(r.source).toBe('generic');
    expect(r.intent).toBe('Allow 0x3333…3333 to spend 5 USDC');
    expect(r.warnings[0]?.code).toBe('generic-interface');
  });

  it('returns unknown when built-ins are disabled and only they would match', async () => {
    const r = await describeTransaction({ chainId: CHAIN, to: OTHER, data: approveData(SPENDER, 1n) }, { builtins: false });
    expect(unknown(r).reason).toBe('no-mapping');
  });

  it('snapshots the intents of every built-in', async () => {
    const calls = [
      transferData(RECIPIENT, 1_000_000n),
      approveData(SPENDER, 1_000_000n),
      transferFromData(OTHER, RECIPIENT, 1_000_000n),
      safeTransferFromData(OTHER, RECIPIENT, 7n),
      `${SEL.safeTransferFrom4}${'0'.repeat(24)}${OTHER.slice(2)}${'0'.repeat(24)}${RECIPIENT.slice(2)}${(7n).toString(16).padStart(64, '0')}${(128n).toString(16).padStart(64, '0')}${(0n).toString(16).padStart(64, '0')}`,
      setApprovalForAllData(SPENDER, true),
    ];
    const intents: string[] = [];
    for (const data of calls) {
      const r = described(await describeTransaction({ chainId: CHAIN, to: OTHER, data }, { resolveToken: resolveUsdc }));
      intents.push(r.intent);
    }
    expect(intents).toMatchInlineSnapshot(`
      [
        "Send 1 USDC to 0x2222…2222",
        "Allow 0x3333…3333 to spend 1 USDC",
        "Transfer 1 USDC from 0x4444…4444 to 0x2222…2222",
        "Transfer collectible #7 from 0x4444…4444 to 0x2222…2222",
        "Transfer collectible #7 from 0x4444…4444 to 0x2222…2222",
        "Set 0x3333…3333 as operator for all your collectibles: true",
      ]
    `);
  });

  it('shows an ERC-721 approve unscaled when the contract has no decimals', async () => {
    const r = described(await describeTransaction({ chainId: CHAIN, to: OTHER, data: approveData(SPENDER, 7n) }, { resolveToken: async () => null }));
    expect(r.intent).toBe('Allow 0x3333…3333 to spend 7');
    expect(r.fields[1]).toEqual({ label: 'Amount', value: '7 (token 0x4444…4444)', kind: 'token-amount', address: '0x4444444444444444444444444444444444444444' });
    expect(r.warnings.map((w) => w.code)).toEqual(['generic-interface', 'token-unresolved']);
  });
});

describe('native transfers', () => {
  it('describes a plain value transfer in the supplied currency', async () => {
    const r = described(
      await describeTransaction({ chainId: CHAIN, to: RECIPIENT, value: 1_500_000_000_000_000_000n, data: '0x' }, { nativeCurrency: { symbol: 'MATIC', decimals: 18 } }),
    );
    expect(r.intent).toBe('Send 1.5 MATIC to 0x2222…2222');
    expect(r.source).toBe('native');
    expect(r.selector).toBeNull();
    expect(r.warnings).toEqual([]);
  });

  it('defaults to ETH and treats missing data as empty', async () => {
    const r = described(await describeTransaction({ chainId: CHAIN, to: RECIPIENT, value: '0xde0b6b3a7640000' }));
    expect(r.intent).toBe('Send 1 ETH to 0x2222…2222');
  });
});

describe('unknown results', () => {
  it('reports no-mapping with selector and raw fields, and no intent', async () => {
    const data = `${SEL.unknown}${'ab'.repeat(32)}`;
    const r = unknown(await describeTransaction({ chainId: CHAIN, to: OTHER, data, value: 5n }, { mappings: [usdcMapping()] }));
    expect(r).toMatchObject({ reason: 'no-mapping', selector: SEL.unknown, contract: '0x4444444444444444444444444444444444444444', raw: { to: OTHER, value: '0x5', data } });
    expect('intent' in r).toBe(false);
  });

  it('reports decode-failed when calldata does not fit the mapped function', async () => {
    const r = unknown(await describeTransaction({ chainId: CHAIN, to: USDC, data: `${SEL.transfer}0000` }, { mappings: [usdcMapping()] }));
    expect(r.reason).toBe('decode-failed');
    expect(r.selector).toBe(SEL.transfer);
    expect(r.raw.data).toBe(`${SEL.transfer}0000`);
  });

  it('reports contract creation when there is no target', async () => {
    const r = unknown(await describeTransaction({ chainId: CHAIN, data: '0x6080604052' }));
    expect(r.reason).toBe('contract-creation');
    expect(r.contract).toBeNull();
  });

  it('never throws on garbage input', async () => {
    const bad = unknown(await describeTransaction({ chainId: CHAIN, to: USDC, data: '0xzz' }));
    expect(bad.reason).toBe('decode-failed');
    const badValue = unknown(await describeTransaction({ chainId: CHAIN, to: USDC, value: 'lots', data: transferData(RECIPIENT, 1n) }));
    expect(badValue.reason).toBe('decode-failed');
    const badTo = unknown(await describeTransaction({ chainId: CHAIN, to: 'nowhere', data: '0x' }));
    expect(badTo.reason).toBe('decode-failed');
    // @ts-expect-error deliberately wrong shape
    const badData = unknown(await describeTransaction({ chainId: CHAIN, to: USDC, data: 42 }));
    expect(badData.reason).toBe('decode-failed');
  });
});

describe('token resolution', () => {
  it('renders unscaled with a warning when the resolver rejects', async () => {
    const r = described(
      await describeTransaction(
        { chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 10_500_000n) },
        { mappings: [usdcMapping()], resolveToken: async () => Promise.reject(new Error('rpc down')) },
      ),
    );
    expect(r.fields[0]).toEqual({ label: 'Amount', value: '10500000 (token 0x1111…1111)', kind: 'token-amount', address: '0x1111111111111111111111111111111111111111' });
    expect(r.warnings.map((w) => w.code)).toEqual(['token-unresolved']);
  });

  it('renders unscaled with a warning when no resolver is supplied', async () => {
    const r = described(await describeTransaction({ chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 10_500_000n) }, { mappings: [usdcMapping()] }));
    expect(r.fields[0]?.value).toBe('10500000 (token 0x1111…1111)');
    expect(r.warnings.map((w) => w.code)).toEqual(['token-unresolved']);
  });

  it('is deterministic for the same input', async () => {
    const input = { chainId: CHAIN, to: USDC, data: transferData(RECIPIENT, 10_500_000n) };
    const opts = { mappings: [usdcMapping()], resolveToken: resolveUsdc };
    expect(await describeTransaction(input, opts)).toEqual(await describeTransaction(input, opts));
  });
});
