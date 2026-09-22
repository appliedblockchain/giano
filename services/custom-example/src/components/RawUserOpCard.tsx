import { Button, HStack, Stack, Steps, Text } from '@chakra-ui/react';
import { useEffect, useRef, useState } from 'react';
import { LuKeyRound, LuSend } from 'react-icons/lu';
import { encodeFunctionData } from 'viem';
import { testErc20Abi } from '../lib/erc20';
import { toJson } from '../lib/format';
import { waitForReceipt } from '../lib/run';
import { useDemo, useSectionEntries } from '../state/store';
import { CodeBlock, Disclosure, Outcomes, SectionCard, StatusText } from './primitives';

/**
 * The three-step pipeline behind eth_sendTransaction, exposed one call at a time so each payload can be
 * inspected before the next: eth_prepareUserOperation → eth_signUserOperation → eth_sendSignedUserOperation.
 * Plus signed_eth_call, the authenticated read.
 */
export function RawUserOpCard() {
  const { selected, account, run, isChainDisabled } = useDemo();
  const entries = useSectionEntries('raw-userop');
  const [prepared, setPrepared] = useState<Record<string, unknown> | null>(null);
  const [signed, setSigned] = useState<Record<string, unknown> | null>(null);
  const [hash, setHash] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  /** The account and chain the pipeline was prepared for: a prepared operation is only valid for those. */
  const [origin, setOrigin] = useState<{ account: string; chainId: number } | null>(null);
  const contextKey = `${selected.chainId}:${account ?? ''}`;
  // The CURRENT context, readable after an await: a closure's `account`/`selected` are frozen at render time,
  // so every state update that follows an await compares against this ref, not against the closure.
  const contextRef = useRef(contextKey);
  contextRef.current = contextKey;
  const stillCurrent = (key: string) => contextRef.current === key;
  useEffect(() => {
    if (origin && (origin.chainId !== selected.chainId || origin.account !== account)) {
      setPrepared(null);
      setSigned(null);
      setHash(null);
      setOrigin(null);
    }
    // Depends on the context key only: `origin` is what this effect resets, not what it reacts to.
  }, [contextKey]);
  const disabled = !account || isChainDisabled(selected.chainId);
  const step = hash ? 3 : signed ? 2 : prepared ? 1 : 0;

  const prepare = async () => {
    if (!account) return;
    const startedIn = contextRef.current;
    setBusy('prepare');
    const calls = [{ to: account, value: '0x0', data: '0x' }];
    const outcome = await run({ section: 'raw-userop', label: 'Prepare user operation', method: 'eth_prepareUserOperation', params: [calls, {}], account, noBalances: true }, (api) =>
      api.provider.request<Record<string, unknown>>({ method: 'eth_prepareUserOperation', params: [calls, {}] }),
    );
    setBusy(null);
    // Discard a result that arrived after the account or chain changed underneath it.
    if (outcome.result && stillCurrent(startedIn)) {
      setPrepared(outcome.result);
      setOrigin({ account, chainId: selected.chainId });
      setSigned(null);
      setHash(null);
    }
  };

  const sign = async () => {
    if (!account || !prepared) return;
    const startedIn = contextRef.current;
    setBusy('sign');
    const outcome = await run({ section: 'raw-userop', label: 'Sign user operation', method: 'eth_signUserOperation', params: [prepared], account, noBalances: true }, (api) =>
      api.provider.request<string>({ method: 'eth_signUserOperation', params: [prepared] }),
    );
    setBusy(null);
    if (outcome.result && stillCurrent(startedIn) && origin && origin.account === account && origin.chainId === selected.chainId) setSigned({ ...prepared, signature: outcome.result });
  };

  const send = async () => {
    if (!account || !signed) return;
    const startedIn = contextRef.current;
    setBusy('send');
    const outcome = await run(
      { section: 'raw-userop', label: 'Send signed user operation', method: 'eth_sendSignedUserOperation', params: [signed], account, declaredPayer: prepared?.paymaster ? 'sponsored' : 'self-paid' },
      async (api) => {
        const opHash = await api.provider.request<string>({ method: 'eth_sendSignedUserOperation', params: [signed] });
        api.update({ userOpHash: opHash, status: 'submitted' });
        if (stillCurrent(startedIn)) setHash(opHash);
        return waitForReceipt(api, opHash);
      },
    );
    setBusy(null);
    if (outcome.error && stillCurrent(startedIn)) setHash(null);
  };

  const signedCall = async () => {
    if (!account) return;
    setBusy('call');
    const token = selected.config.defaultToken;
    const call = token
      ? { to: token, data: encodeFunctionData({ abi: testErc20Abi, functionName: 'privateBalanceOf', args: [account] }) }
      : { to: account, data: encodeFunctionData({ abi: testErc20Abi, functionName: 'balanceOf', args: [account] }) };
    await run({ section: 'raw-userop', label: token ? 'signed_eth_call · privateBalanceOf' : 'signed_eth_call (no default token on this chain)', method: 'signed_eth_call', params: [call], account, noBalances: true }, (api) =>
      api.provider.request<string>({ method: 'signed_eth_call', params: [call] }),
    );
    setBusy(null);
  };

  const invalidSignedCall = () =>
    run({ section: 'raw-userop', label: 'signed_eth_call without to/data (validation expected)', method: 'signed_eth_call', params: [{}], account, expected: true, noBalances: true }, (api) =>
      api.provider.request<string>({ method: 'signed_eth_call', params: [{}] }),
    );

  return (
    <SectionCard
      id="raw-userop"
      title="Raw user operation"
      description="The three-step pipeline behind eth_sendTransaction, exposed one call at a time so each payload can be inspected before the next."
      sdk={[
        ['eth_prepareUserOperation', 'estimate gas and assemble the unsigned user operation (with paymaster data when sponsored)'],
        ['eth_signUserOperation', 'sign it with the passkey in the wallet popup'],
        ['eth_sendSignedUserOperation', 'submit the signed operation; returns its hash'],
        ['signed_eth_call', 'an authenticated read: the wallet signs a static-call permission so a contract can gate a view by caller'],
      ]}
    >
      <Steps.Root step={step} count={3} size="sm" colorPalette="brand">
        <Steps.List>
          {['eth_prepareUserOperation', 'eth_signUserOperation', 'eth_sendSignedUserOperation'].map((title, index) => (
            <Steps.Item key={title} index={index} title={title}>
              <Steps.Indicator />
              <Steps.Title fontFamily="mono" fontSize="xs">
                {title}
              </Steps.Title>
              <Steps.Separator />
            </Steps.Item>
          ))}
        </Steps.List>
      </Steps.Root>

      <Stack gap="3">
        <HStack gap="3" flexWrap="wrap">
          <Button size="sm" variant={step === 0 ? 'solid' : 'outline'} colorPalette="brand" onClick={() => void prepare()} disabled={disabled} loading={busy === 'prepare'}>
            1 · Prepare (0 ETH to self)
          </Button>
          <Button size="sm" variant={step === 1 ? 'solid' : 'outline'} colorPalette="brand" onClick={() => void sign()} disabled={disabled || !prepared} loading={busy === 'sign'} loadingText="Awaiting wallet…">
            <LuKeyRound /> 2 · Sign
          </Button>
          <Button size="sm" variant={step === 2 ? 'solid' : 'outline'} colorPalette="brand" onClick={() => void send()} disabled={disabled || !signed} loading={busy === 'send'} loadingText="Awaiting receipt…">
            <LuSend /> 3 · Send signed and wait
          </Button>
          {(prepared || signed || hash) && (
            <Button
              size="sm"
              variant="ghost"
              colorPalette="gray"
              onClick={() => {
                setPrepared(null);
                setSigned(null);
                setHash(null);
              }}
            >
              Reset
            </Button>
          )}
        </HStack>
        {prepared && !signed && <Disclosure label="Prepared user operation (payload)"><CodeBlock value={toJson(prepared)} /></Disclosure>}
        {signed && <Disclosure label="Signed user operation (payload)"><CodeBlock value={toJson(signed)} /></Disclosure>}
        {hash && <StatusText tone="green">userOp {hash}</StatusText>}
      </Stack>

      <HStack gap="3" flexWrap="wrap" align="center">
        <Text fontSize="sm" fontWeight="medium">
          signed_eth_call
        </Text>
        <Button size="sm" variant="outline" onClick={() => void signedCall()} disabled={disabled} loading={busy === 'call'}>
          Call privateBalanceOf on the default token
        </Button>
        <Button size="sm" variant="ghost" colorPalette="gray" onClick={() => void invalidSignedCall()} disabled={disabled}>
          Call without to/data (validation error expected)
        </Button>
      </HStack>

      <Outcomes entries={entries} />
    </SectionCard>
  );
}
