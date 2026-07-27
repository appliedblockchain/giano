import { useEffect, useState } from 'react';
import { Badge, Button, HStack, Input, Separator, Stack, Text } from '@chakra-ui/react';
import { LuBadgeCheck, LuDownload, LuRefreshCw, LuSend, LuSignature } from 'react-icons/lu';
import { encodeFunctionData, erc20Abi, formatUnits, getAddress, isAddress, parseUnits } from 'viem';
import { Field } from './ui/field';
import { provider, publicClient } from '../giano';
import { notifyError, notifyInfo, notifySuccess } from '../lib/notify';
import { ResultBox } from './ResultBox';
import { SectionCard } from './SectionCard';

type Address = `0x${string}`;

// EIP-2612 fragment — the repo has no permit helper, so we read nonces / submit permit locally.
const erc2612Abi = [
  { type: 'function', name: 'nonces', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }], outputs: [{ type: 'uint256' }] },
  {
    type: 'function',
    name: 'permit',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'deadline', type: 'uint256' },
      { name: 'v', type: 'uint8' },
      { name: 'r', type: 'bytes32' },
      { name: 's', type: 'bytes32' },
    ],
    outputs: [],
  },
] as const;

type TokenMeta = { name: string; symbol: string; decimals: number };

export function Erc20Panel({ account, defaultToken }: { account: Address; defaultToken: Address }) {
  const [tokenInput, setTokenInput] = useState<string>(defaultToken);
  const [token, setToken] = useState<Address | null>(null);
  const [meta, setMeta] = useState<TokenMeta | null>(null);
  const [balance, setBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);

  const [destination, setDestination] = useState<string>(account);
  const [amount, setAmount] = useState<string>('1');

  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<'transfer' | 'approve' | 'permit-sign' | null>(null);
  const [txResult, setTxResult] = useState('');
  const [permitSig, setPermitSig] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    setDestination((prev) => prev || account);
  }, [account]);

  const amountWei = (): bigint => parseUnits(amount || '0', meta?.decimals ?? 18);

  const loadToken = async () => {
    if (!isAddress(tokenInput)) {
      setError(notifyError('Invalid token address', new Error(tokenInput)));
      return;
    }
    const address = getAddress(tokenInput);
    setLoading(true);
    setError('');
    try {
      const [name, symbol, decimals, bal] = await Promise.all([
        publicClient.readContract({ address, abi: erc20Abi, functionName: 'name' }),
        publicClient.readContract({ address, abi: erc20Abi, functionName: 'symbol' }),
        publicClient.readContract({ address, abi: erc20Abi, functionName: 'decimals' }),
        publicClient.readContract({ address, abi: erc20Abi, functionName: 'balanceOf', args: [account] }),
      ]);
      setToken(address);
      setMeta({ name, symbol, decimals });
      setBalance(bal);
      setAllowance(null);
      setPermitSig('');
      notifySuccess(`Loaded ${symbol}`, `${name} · ${decimals} decimals`);
    } catch (err) {
      setToken(null);
      setMeta(null);
      setError(notifyError('Could not read token', err));
    } finally {
      setLoading(false);
    }
  };

  const refresh = async () => {
    if (!token) return;
    try {
      const bal = await publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [account] });
      setBalance(bal);
      if (isAddress(destination)) {
        const allow = await publicClient.readContract({
          address: token,
          abi: erc20Abi,
          functionName: 'allowance',
          args: [account, getAddress(destination)],
        });
        setAllowance(allow);
      }
    } catch (err) {
      setError(notifyError('Refresh failed', err));
    }
  };

  // Submit a tx through the wallet popup, show the userOp hash, then wait for the receipt.
  const sendAndWait = async (to: Address, data: Address, label: string): Promise<boolean> => {
    setTxResult('');
    const hash = await provider.request<string>({ method: 'eth_sendTransaction', params: [{ to, data }] });
    setTxResult(`${label}\nuserOp: ${hash}`);
    notifyInfo(`${label} submitted`, `userOp ${hash} — waiting for receipt…`);
    const receipt = await provider.request<{ success: boolean }>({ method: 'waitForUserOperationReceipt', params: [hash] });
    setTxResult(`${label}\nuserOp: ${hash}\nsuccess: ${receipt.success}`);
    return receipt.success;
  };

  const guardDestination = (): Address | null => {
    if (!isAddress(destination)) {
      setError(notifyError('Invalid destination address', new Error(destination)));
      return null;
    }
    return getAddress(destination);
  };

  const transfer = async () => {
    if (!token) return;
    const to = guardDestination();
    if (!to) return;
    setBusy('transfer');
    setError('');
    try {
      const data = encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [to, amountWei()] }) as Address;
      const ok = await sendAndWait(token, data, 'Transfer');
      if (ok) notifySuccess('Transfer confirmed');
      else setError(notifyError('Transfer reverted', new Error('user-operation reverted on-chain')));
      await refresh();
    } catch (err) {
      setError(notifyError('Transfer failed', err));
    } finally {
      setBusy(null);
    }
  };

  const approve = async () => {
    if (!token) return;
    const spender = guardDestination();
    if (!spender) return;
    setBusy('approve');
    setError('');
    try {
      const data = encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [spender, amountWei()] }) as Address;
      const ok = await sendAndWait(token, data, 'Approve');
      if (ok) notifySuccess('Approval confirmed');
      else setError(notifyError('Approval reverted', new Error('user-operation reverted on-chain')));
      await refresh();
    } catch (err) {
      setError(notifyError('Approval failed', err));
    } finally {
      setBusy(null);
    }
  };

  const signPermit = async () => {
    if (!token || !meta) return;
    const spender = guardDestination();
    if (!spender) return;
    setBusy('permit-sign');
    setPermitSig('');
    setError('');
    try {
      // nonces() only exists on EIP-2612 tokens; a revert here means the token has no permit.
      let nonce: bigint;
      try {
        nonce = await publicClient.readContract({ address: token, abi: erc2612Abi, functionName: 'nonces', args: [account] });
      } catch {
        setError(notifyError('No permit support', new Error(`${meta.symbol} does not implement EIP-2612 permit (no nonces()).`)));
        return;
      }
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
      const value = amountWei();
      const typedData = JSON.stringify({
        domain: { name: meta.name, version: '1', chainId: publicClient.chain.id, verifyingContract: token },
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
        message: { owner: account, spender, value: value.toString(), nonce: nonce.toString(), deadline: deadline.toString() },
      });
      // Giano is a smart-contract account: the signature is an ERC-1271 / WebAuthn blob, NOT an
      // ECDSA v/r/s triple — so we display the raw signature rather than trying to split it.
      const signature = await provider.request<string>({ method: 'eth_signTypedData_v4', params: [account, typedData] });
      setPermitSig(
        `spender: ${spender}\n` +
          `value:   ${value.toString()}\n` +
          `nonce:   ${nonce.toString()}\n` +
          `deadline: ${deadline.toString()}\n` +
          `signature (ERC-1271): ${signature}`,
      );
      notifySuccess('Permit signed', `nonce ${nonce.toString()}, deadline ${deadline.toString()}`);
    } catch (err) {
      setError(notifyError('Permit signing failed', err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <SectionCard title="ERC-20 token" description="Enter a token address, then read balances and move / approve / permit tokens.">
      <Stack gap="5">
        <Stack gap="2">
          <Field label="Token address">
            <Input value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} placeholder="0x…" fontFamily="mono" bg="white" />
          </Field>
          <HStack>
            <Button colorPalette="brand" onClick={loadToken} loading={loading} loadingText="Loading…">
              <LuDownload /> Load token
            </Button>
            {token && (
              <Button variant="ghost" colorPalette="brand" onClick={refresh}>
                <LuRefreshCw /> Refresh
              </Button>
            )}
          </HStack>
          {meta && (
            <HStack gap="2" flexWrap="wrap">
              <Badge colorPalette="brand">{meta.name}</Badge>
              <Badge colorPalette="brand" variant="surface">
                {meta.symbol}
              </Badge>
              <Text fontSize="sm" color="fg.muted">
                Balance: <b>{balance !== null ? formatUnits(balance, meta.decimals) : '—'}</b> {meta.symbol}
              </Text>
              {allowance !== null && (
                <Text fontSize="sm" color="fg.muted">
                  · Allowance: <b>{formatUnits(allowance, meta.decimals)}</b>
                </Text>
              )}
            </HStack>
          )}
        </Stack>

        {token && meta && (
          <>
            <Separator />
            <Stack direction={{ base: 'column', md: 'row' }} gap="3">
              <Field label="Destination / spender" helperText="Defaults to your own account.">
                <Input value={destination} onChange={(e) => setDestination(e.target.value)} placeholder="0x…" fontFamily="mono" bg="white" />
              </Field>
              <Field label={`Amount (${meta.symbol})`} width={{ base: 'full', md: '40%' }}>
                <Input value={amount} onChange={(e) => setAmount(e.target.value)} type="number" min="0" bg="white" />
              </Field>
            </Stack>

            <Stack direction={{ base: 'column', sm: 'row' }} gap="3" flexWrap="wrap">
              <Button colorPalette="brand" onClick={transfer} loading={busy === 'transfer'} disabled={busy !== null}>
                <LuSend /> Transfer
              </Button>
              <Button variant="outline" colorPalette="brand" onClick={approve} loading={busy === 'approve'} disabled={busy !== null}>
                <LuBadgeCheck /> Approve (tx)
              </Button>
              <Button variant="outline" colorPalette="accent" onClick={signPermit} loading={busy === 'permit-sign'} disabled={busy !== null}>
                <LuSignature /> Sign permit (EIP-2612)
              </Button>
            </Stack>

            {txResult && <ResultBox label="Transaction" value={txResult} />}
            {permitSig && <ResultBox label="Permit signature" value={permitSig} tone="accent" />}
          </>
        )}

        {error && <ResultBox label="Error" value={error} tone="error" />}
      </Stack>
    </SectionCard>
  );
}
