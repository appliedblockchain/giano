import { useState } from 'react';
import { Button, Input, Stack, Text } from '@chakra-ui/react';
import { LuPenLine, LuSend } from 'react-icons/lu';
import { toBytes, toHex } from 'viem';
import { Field } from './ui/field';
import { chain } from '../config';
import { provider } from '../giano';
import { notifyError, notifyInfo, notifySuccess } from '../lib/notify';
import { ResultBox } from './ResultBox';
import { SectionCard } from './SectionCard';

type Address = `0x${string}`;

export function WalletPanel({ account }: { account: Address }) {
  const [message, setMessage] = useState('Hello from the Giano demo!');
  const [sending, setSending] = useState(false);
  const [signing, setSigning] = useState<'message' | 'typed' | null>(null);
  const [txResult, setTxResult] = useState('');
  const [signature, setSignature] = useState('');
  const [error, setError] = useState('');

  const sendZeroEth = async () => {
    setSending(true);
    setTxResult('');
    setError('');
    try {
      const hash = await provider.request<string>({
        method: 'eth_sendTransaction',
        params: [{ to: account, value: '0x0' }],
      });
      setTxResult(`userOp: ${hash}`);
      notifyInfo('Transaction submitted', `userOp ${hash} — waiting for receipt…`);
      const receipt = await provider.request<{ success: boolean }>({ method: 'waitForUserOperationReceipt', params: [hash] });
      setTxResult(`userOp: ${hash}\nsuccess: ${receipt.success}`);
      if (receipt.success) notifySuccess('Transaction confirmed');
      else setError(notifyError('Transaction reverted', new Error('user-operation reverted on-chain')));
    } catch (err) {
      setError(notifyError('Send failed', err));
    } finally {
      setSending(false);
    }
  };

  const signMessage = async () => {
    setSigning('message');
    setError('');
    try {
      const sig = await provider.request<string>({ method: 'personal_sign', params: [toHex(toBytes(message)), account] });
      setSignature(sig);
      notifySuccess('Message signed');
    } catch (err) {
      setError(notifyError('Signing failed', err));
    } finally {
      setSigning(null);
    }
  };

  const signTypedData = async () => {
    setSigning('typed');
    setError('');
    try {
      const typedData = JSON.stringify({
        domain: { name: 'Giano Demo', version: '1', chainId: chain.id },
        types: { Greeting: [{ name: 'text', type: 'string' }] },
        primaryType: 'Greeting',
        message: { text: message },
      });
      const sig = await provider.request<string>({ method: 'eth_signTypedData_v4', params: [account, typedData] });
      setSignature(sig);
      notifySuccess('Typed data signed');
    } catch (err) {
      setError(notifyError('Signing failed', err));
    } finally {
      setSigning(null);
    }
  };

  return (
    <SectionCard title="Wallet basics" description="The minimal set of wallet interactions.">
      <Stack gap="5">
        <Stack gap="1">
          <Text fontWeight="medium">Send transaction</Text>
          <Text fontSize="sm" color="fg.muted">
            Sends a 0 ETH user-operation to your own account — the simplest way to exercise the smart wallet.
          </Text>
          <Button mt="2" colorPalette="brand" onClick={sendZeroEth} loading={sending} loadingText="Sending…" alignSelf="flex-start">
            <LuSend /> Send 0 ETH to self
          </Button>
          {txResult && <ResultBox label="Transaction" value={txResult} />}
        </Stack>

        <Stack gap="2">
          <Field label="Message">
            <Input value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Message to sign" bg="white" />
          </Field>
          <Stack direction={{ base: 'column', sm: 'row' }} gap="3">
            <Button
              variant="outline"
              colorPalette="brand"
              onClick={signMessage}
              loading={signing === 'message'}
              disabled={!message.trim() || signing !== null}
            >
              <LuPenLine /> Sign message
            </Button>
            <Button
              variant="outline"
              colorPalette="brand"
              onClick={signTypedData}
              loading={signing === 'typed'}
              disabled={!message.trim() || signing !== null}
            >
              <LuPenLine /> Sign typed data (EIP-712)
            </Button>
          </Stack>
          {signature && <ResultBox label="Signature" value={signature} />}
        </Stack>

        {error && <ResultBox label="Error" value={error} tone="error" />}
      </Stack>
    </SectionCard>
  );
}
