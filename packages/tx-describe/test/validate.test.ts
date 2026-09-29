import { describe, expect, it } from 'vitest';
import { canonicalSignature, checksumAddress, deploymentsOf, formatUnits, functionSelector, mappingCovers, validateMapping } from '../src/index';
import { CHAIN, USDC, usdcMapping } from './fixtures';

describe('validateMapping', () => {
  it('accepts a valid descriptor', () => {
    expect(validateMapping(usdcMapping())).toEqual({ ok: true, issues: [] });
  });

  it('accepts a selector-keyed format', () => {
    const m = usdcMapping();
    const spec = m.display!.formats!['transfer(address to, uint256 value)']!;
    m.display!.formats = { '0xa9059cbb': spec };
    expect(validateMapping(m).ok).toBe(true);
  });

  it('rejects a missing deployment binding with a path', () => {
    const m = usdcMapping({ context: { contract: { deployments: [], abi: usdcMapping().context!.contract!.abi } } as never });
    const r = validateMapping(m);
    expect(r.ok).toBe(false);
    expect(r.issues).toEqual([{ path: 'context.contract.deployments', message: 'at least one deployment binding is required' }]);
  });

  it('rejects a field path that is not an input of the function', () => {
    const m = usdcMapping();
    (m.display!.formats!['transfer(address to, uint256 value)']!.fields as Array<{ path: string }>)[1]!.path = 'recipient';
    const r = validateMapping(m);
    expect(r.ok).toBe(false);
    expect(r.issues[0]).toEqual({
      path: 'display.formats.transfer(address to, uint256 value).fields[1].path',
      message: '"recipient" does not name an input of transfer(address,uint256) (inputs: to, value)',
    });
  });

  it('rejects a function key that is neither a selector nor a signature', () => {
    const m = usdcMapping();
    m.display!.formats = { transfer: m.display!.formats!['transfer(address to, uint256 value)']! };
    const r = validateMapping(m);
    expect(r.ok).toBe(false);
    expect(r.issues[0]?.path).toBe('display.formats.transfer');
    expect(r.issues[0]?.message).toContain('not a selector or a function signature');
  });

  it('rejects a function key that is not in the ABI', () => {
    const m = usdcMapping();
    m.display!.formats = { 'burn(uint256 value)': { intent: 'Burn', fields: [{ path: 'value', label: 'Amount', format: 'raw' }] } };
    const r = validateMapping(m);
    expect(r.ok).toBe(false);
    expect(r.issues[0]?.message).toContain('no function in the ABI matches burn(uint256) (0x42966c68)');
  });

  it('rejects a format with no intent', () => {
    const m = usdcMapping();
    delete (m.display!.formats!['transfer(address to, uint256 value)'] as { intent?: unknown }).intent;
    delete (m.display!.formats!['transfer(address to, uint256 value)'] as { interpolatedIntent?: unknown }).interpolatedIntent;
    const r = validateMapping(m);
    expect(r.ok).toBe(false);
    expect(r.issues[0]?.path).toBe('display.formats.transfer(address to, uint256 value).intent');
  });

  it('rejects includes and a URL abi', () => {
    const withIncludes = validateMapping(usdcMapping({ includes: '../erc20.json' }));
    expect(withIncludes.ok).toBe(false);
    expect(withIncludes.issues[0]?.path).toBe('includes');
    const urlAbi = validateMapping(usdcMapping({ context: { contract: { deployments: [{ chainId: CHAIN, address: USDC }], abi: 'https://example.com/abi.json' } } as never }));
    expect(urlAbi.ok).toBe(false);
    expect(urlAbi.issues[0]?.path).toBe('context.contract.abi');
  });

  it('reports non-object input at the root', () => {
    const r = validateMapping('nope');
    expect(r.ok).toBe(false);
    expect(r.issues[0]?.path).toBe('(root)');
  });

  it('accepts container and metadata paths', () => {
    const m = usdcMapping();
    (m.display!.formats!['transfer(address to, uint256 value)']!.fields as Array<{ path: string }>).push({ path: '@.value' } as never, { path: '$.metadata.owner' } as never);
    expect(validateMapping(m).ok).toBe(true);
  });
});

describe('helpers', () => {
  it('computes selectors from signatures with names, tuples and arrays', () => {
    expect(functionSelector('transfer(address to, uint256 value)')).toBe('0xa9059cbb');
    expect(functionSelector('function transfer(address,uint256)')).toBe('0xa9059cbb');
    expect(functionSelector('0xA9059CBB')).toBe('0xa9059cbb');
    expect(canonicalSignature('swap((address a, uint256 b)[] items, bytes data)')).toBe('swap((address,uint256)[],bytes)');
    expect(canonicalSignature('f(uint x, int y)')).toBe('f(uint256,int256)');
    expect(() => functionSelector('transfer')).toThrow();
  });

  it('checksums and formats units', () => {
    expect(checksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359')).toBe('0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
    expect(formatUnits(10_500_000n, 6)).toBe('10.5');
    expect(formatUnits(0n, 18)).toBe('0');
    expect(formatUnits(1n, 18)).toBe('0.000000000000000001');
    expect(formatUnits(12345n, 0)).toBe('12345');
  });

  it('reads deployments and coverage', () => {
    expect(deploymentsOf(usdcMapping())).toEqual([{ chainId: CHAIN, address: USDC }]);
    expect(mappingCovers(usdcMapping(), CHAIN, USDC.toUpperCase().replace('0X', '0x'))).toBe(true);
    expect(mappingCovers(usdcMapping(), 1, USDC)).toBe(false);
    expect(deploymentsOf({} as never)).toEqual([]);
  });
});
