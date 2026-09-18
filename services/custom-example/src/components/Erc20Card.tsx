import { Button, HStack, Input, Stack, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useState } from 'react';
import { LuDownload, LuRefreshCw, LuSend } from 'react-icons/lu';
import { encodeFunctionData, getAddress, isAddress, parseUnits } from 'viem';
import { erc2612Abi, erc20Abi, testErc20Abi } from '../lib/erc20';
import { formatToken, type Address, type Hex } from '../lib/format';
import type { Payer } from '../lib/receipt';
import { submitTransaction } from '../lib/run';
import { useDemo, useSectionEntries, useSettledCount } from '../state/store';
import { ActionPicker, Mono, Outcomes, SectionCard, StatusText } from './primitives';
import { Field } from './ui/field';

type TokenMeta = { name: string; symbol: string; decimals: number };
type Op = 'mint' | 'transfer' | 'approve' | 'permit';

const OPS: Array<{ value: Op; label: string }> = [
  { value: 'mint', label: 'Mint to self' },
  { value: 'transfer', label: 'Transfer' },
  { value: 'approve', label: 'Approve' },
  { value: 'permit', label: 'Sign permit (EIP-2612)' },
];

/** R13/R14: a token section with a per-chain default (Giano's test ERC-20, same CREATE2 address everywhere), anyone can mint it. */
export function Erc20Card() {
  const { registry, selected, account, run, isChainDisabled } = useDemo();
  const entries = useSectionEntries('erc20');
  const settled = useSettledCount();
  const entry = registry.get(selected.chainId);
  const defaultToken = selected.config.defaultToken;

  const [tokenInput, setTokenInput] = useState<string>(defaultToken ?? '');
  const [token, setToken] = useState<Address | null>(null);
  const [meta, setMeta] = useState<TokenMeta | null>(null);
  const [balance, setBalance] = useState<bigint | undefined>();
  const [allowance, setAllowance] = useState<bigint | undefined>();
  const [op, setOp] = useState<Op>('mint');
  const [destination, setDestination] = useState('');
  const [amount, setAmount] = useState('100');
  const [busy, setBusy] = useState(false);
  const [payer, setPayer] = useState<Payer>('sponsored');

  useEffect(() => {
    setTokenInput(defaultToken ?? '');
    setToken(null);
    setMeta(null);
  }, [defaultToken, selected.chainId]);
  useEffect(() => {
    if (account && !destination) setDestination(account);
  }, [account, destination]);

  const refresh = useCallback(async () => {
    if (!entry || !token || !account) return;
    const [bal, allow] = await Promise.all([
      entry.publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [account] }).catch(() => undefined),
      isAddress(destination) ? entry.publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'allowance', args: [account, getAddress(destination)] }).catch(() => undefined) : Promise.resolve(undefined),
    ]);
    setBalance(bal);
    setAllowance(allow);
  }, [entry, token, account, destination]);
  useEffect(() => {
    void refresh();
  }, [refresh, settled]);

  const load = async () => {
    if (!entry) return;
    if (!isAddress(tokenInput)) {
      await run({ section: 'erc20', label: 'Load token (invalid address)', method: 'readContract', params: { token: tokenInput }, account, noBalances: true }, async () => {
        throw new Error(`"${tokenInput}" is not a valid address`);
      });
      return;
    }
    const address = getAddress(tokenInput);
    const outcome = await run({ section: 'erc20', label: 'Load token', method: 'readContract name/symbol/decimals/balanceOf', params: { token: address }, account, noBalances: true }, async () => {
      const [name, symbol, decimals, bal] = await Promise.all([
        entry.publicClient.readContract({ address, abi: erc20Abi, functionName: 'name' }),
        entry.publicClient.readContract({ address, abi: erc20Abi, functionName: 'symbol' }),
        entry.publicClient.readContract({ address, abi: erc20Abi, functionName: 'decimals' }),
        account ? entry.publicClient.readContract({ address, abi: erc20Abi, functionName: 'balanceOf', args: [account] }) : Promise.resolve(undefined),
      ]);
      return { name, symbol, decimals, balance: bal?.toString() };
    });
    if (outcome.result) {
      setToken(address);
      setMeta({ name: outcome.result.name, symbol: outcome.result.symbol, decimals: outcome.result.decimals });
    } else {
      setToken(null);
      setMeta(null);
    }
  };

  const execute = async () => {
    if (!account || !token || !meta) return;
    const units = parseUnits(amount || '0', meta.decimals);
    setBusy(true);
    try {
      if (op === 'mint') {
        const data = encodeFunctionData({ abi: testErc20Abi, functionName: 'mint', args: [units] }) as Hex;
        await run({ section: 'erc20', label: `Mint ${amount} ${meta.symbol}`, method: 'eth_sendTransaction', params: [{ to: token, data }], account, token, declaredPayer: payer, sponsoredSend: payer === 'sponsored' }, (api) =>
          submitTransaction(api, { to: token, data }),
        );
        return;
      }
      if (!isAddress(destination)) {
        await run({ section: 'erc20', label: `${op} (invalid destination)`, method: 'eth_sendTransaction', params: { destination }, account, noBalances: true }, async () => {
          throw new Error(`"${destination}" is not a valid address`);
        });
        return;
      }
      const target = getAddress(destination);
      if (op === 'transfer' || op === 'approve') {
        const data = encodeFunctionData({ abi: erc20Abi, functionName: op, args: [target, units] }) as Hex;
        await run(
          { section: 'erc20', label: `${op === 'transfer' ? 'Transfer' : 'Approve'} ${amount} ${meta.symbol} → ${target.slice(0, 8)}…`, method: 'eth_sendTransaction', params: [{ to: token, data }], account, token, declaredPayer: payer, sponsoredSend: payer === 'sponsored' },
          (api) => submitTransaction(api, { to: token, data }),
        );
        return;
      }
      // permit: nonces() doubles as the probe for EIP-2612 support — no popup when it is absent.
      await run({ section: 'erc20', label: `Sign permit for ${amount} ${meta.symbol}`, method: 'eth_signTypedData_v4', account, token, noBalances: true }, async (api) => {
        let nonce: bigint;
        try {
          nonce = await api.entry.publicClient.readContract({ address: token, abi: erc2612Abi, functionName: 'nonces', args: [account] });
        } catch (error) {
          api.update({ note: `${meta.symbol} has no nonces(): no EIP-2612 permit support. No popup was opened.` });
          throw new Error(`${meta.symbol} does not implement EIP-2612 (nonces() reverted): ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`);
        }
        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
        const typedData = {
          domain: { name: meta.name, version: '1', chainId: selected.chainId, verifyingContract: token },
          types: {
            Permit: [
              { name: 'owner', type: 'address' },
              { name: 'spender', type: 'address' },
              { name: 'value', type: 'uint256' },
              { name: 'nonce', type: 'uint256' },
              { name: 'deadline', type: 'uint256' },
            ],
          },
          primaryType: 'Permit',
          message: { owner: account, spender: target, value: units.toString(), nonce: nonce.toString(), deadline: deadline.toString() },
        };
        api.update({ params: [account, typedData] });
        const signature = await api.provider.request<string>({ method: 'eth_signTypedData_v4', params: [account, JSON.stringify(typedData)] });
        return { signature, nonce: nonce.toString(), deadline: deadline.toString(), note: 'ERC-1271 signature from a smart account — not an ECDSA v/r/s triple' };
      });
    } finally {
      setBusy(false);
    }
  };

  const disabled = !account || isChainDisabled(selected.chainId);

  return (
    <SectionCard
      id="erc20"
      title="Test token"
      description="Prefilled with this chain's default token — Giano's test ERC-20, at the same address on every chain. Anyone can mint it; every operation records the token balance before and after."
      sdk={[
        ['eth_sendTransaction', 'mint / transfer / approve, encoded as contract calls'],
        ['eth_signTypedData_v4', 'the EIP-2612 permit signature'],
        ['publicClient.readContract', 'name, symbol, decimals, balances and allowance, read dApp-side'],
      ]}
    >
      {!defaultToken && <StatusText tone="orange">No default token is configured for {selected.config.name}. Enter any token address below.</StatusText>}
      <HStack gap="3" align="flex-end" flexWrap="wrap">
        <Field label="Token address" flex="1" minW="72">
          <Input fontFamily="mono" value={tokenInput} placeholder="0x…" onChange={(event) => setTokenInput(event.target.value)} />
        </Field>
        <Button colorPalette="brand" onClick={() => void load()} disabled={isChainDisabled(selected.chainId)} data-testid="load-token">
          <LuDownload /> Load
        </Button>
        {token && (
          <Button variant="ghost" colorPalette="gray" onClick={() => void refresh()} aria-label="Refresh">
            <LuRefreshCw />
          </Button>
        )}
      </HStack>

      {token && meta && (
        <Stack gap="4">
          <HStack gap="4" flexWrap="wrap">
            <Text fontSize="sm" fontWeight="medium">
              {meta.name} · {meta.symbol} · {meta.decimals} decimals
            </Text>
            <HStack gap="2">
              <Text fontSize="sm" color="fg.muted">
                Balance
              </Text>
              <Mono size="sm">{account ? formatToken(balance, meta.decimals, meta.symbol) : '—'}</Mono>
            </HStack>
            <HStack gap="2">
              <Text fontSize="sm" color="fg.muted">
                Allowance
              </Text>
              <Mono size="sm">{formatToken(allowance, meta.decimals, meta.symbol)}</Mono>
            </HStack>
          </HStack>
          <HStack gap="3" align="flex-end" flexWrap="wrap">
            <Field label="Destination / spender" helperText="Defaults to your own account." flex="2" minW="64">
              <Input fontFamily="mono" value={destination} onChange={(event) => setDestination(event.target.value)} disabled={op === 'mint'} />
            </Field>
            <Field label={`Amount (${meta.symbol})`} w="32">
              <Input fontFamily="mono" value={amount} onChange={(event) => setAmount(event.target.value)} />
            </Field>
          </HStack>
          <HStack gap="3" align="flex-end" flexWrap="wrap">
            <Field label="Action">
              <ActionPicker label="Action" value={op} options={OPS} onChange={setOp} />
            </Field>
            {op !== 'permit' && (
              <Field label="Gas payer">
                <ActionPicker label="Gas payer" value={payer} options={[{ value: 'sponsored', label: 'Sponsored by the app' }, { value: 'self-paid', label: 'Paid by this account' }]} onChange={setPayer} />
              </Field>
            )}
            <Button colorPalette="brand" onClick={() => void execute()} disabled={disabled || busy} loading={busy} loadingText="Awaiting wallet…" data-testid="erc20-run">
              <LuSend /> Run
            </Button>
          </HStack>
        </Stack>
      )}

      <Outcomes entries={entries} />
    </SectionCard>
  );
}
