import { ChainType, depositPasskeyIntoPendingAddition, type WalletManagementApi } from '@appliedblockchain/giano-wallet-core';
import { useState } from 'react';
import type { WalletRuntime } from '../../wallet';
import { FlowShell, manageLog } from './shared';

/**
 * The NEW device's half of a cross-device addition (D8, phase 4): enter the claim code
 * shown on the authorising device, create a passkey, deposit it — and then display the
 * fingerprint for the user to compare over on the other screen (WM-20). Nothing here
 * needs or receives a session: the code routes, it does not authorise (WM-19).
 */
export function ClaimFlow({ api, runtime, brand, onBack }: { api: WalletManagementApi; runtime: WalletRuntime; brand: string; onBack: () => void }) {
  type Stage =
    | { step: 'input' }
    | { step: 'depositing' }
    | { step: 'deposited'; fingerprint: string }
    | { step: 'error'; code?: string; message: string };

  const [stage, setStage] = useState<Stage>({ step: 'input' });
  const [code, setCode] = useState('');

  const deposit = async () => {
    setStage({ step: 'depositing' });
    try {
      const userId = await runtime.injection.encodeUserId(crypto.randomUUID().replace(/-/g, ''), runtime.factoryAddress, ChainType.EVM);
      const deposited = await depositPasskeyIntoPendingAddition({
        api,
        claimCode: code,
        userId,
        userName: brand,
      });
      manageLog('claim: passkey created and deposited', { fingerprint: deposited.fingerprint });
      setStage({ step: 'deposited', fingerprint: deposited.fingerprint });
    } catch (error) {
      const apiCode = (error as { code?: string }).code;
      manageLog('claim: failed', { code: apiCode, message: (error as Error).message });
      setStage({ step: 'error', code: apiCode, message: (error as Error).message });
    }
  };

  if (stage.step === 'input' || stage.step === 'depositing') {
    return (
      <FlowShell title="Add this device to an existing wallet">
        <p>Enter the code shown on the device that already holds a passkey for the wallet. Both devices need to stay open.</p>
        <input
          value={code}
          onChange={(event) => setCode(event.target.value)}
          placeholder="e.g. AB3D-9KFM"
          autoCapitalize="characters"
          style={{ width: '100%', borderRadius: 8, border: '1px solid var(--border)', padding: '10px', background: 'var(--bg)', color: 'var(--fg)', fontFamily: 'ui-monospace, monospace', fontSize: 18, textAlign: 'center', letterSpacing: 2 }}
          data-testid="manage-claim-input"
        />
        <div className="actions">
          <button onClick={onBack}>Back</button>
          <button className="primary" onClick={() => void deposit()} disabled={stage.step === 'depositing' || code.trim().length < 4} data-testid="manage-claim-continue">
            {stage.step === 'depositing' ? 'Creating passkey…' : 'Create a passkey here'}
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'deposited') {
    return (
      <FlowShell title="Now compare the fingerprints">
        <p>
          This device created a passkey with the fingerprint below. Your other device will show the fingerprint of the
          key it is being asked to add — approve there <b>only if the two match</b>.
        </p>
        <div className="data-box" style={{ fontSize: 26, textAlign: 'center', letterSpacing: 3 }} data-testid="manage-claim-fingerprint">
          {stage.fingerprint}
        </div>
        <p data-testid="manage-claim-next">
          Once it is approved and confirmed on-chain, come back here and choose <b>“Use a passkey created on another
          device”</b> to sign in with it.
        </p>
        <div className="actions">
          <button className="primary" onClick={onBack} data-testid="manage-flow-done">
            Done
          </button>
        </div>
      </FlowShell>
    );
  }

  // WM-23: an expired, unknown or already-used code is refused with a reason the user can
  // act on — visibly different from a network failure.
  const explanation =
    stage.code === 'pending-expired'
      ? 'The code expired. Ask your other device for a fresh one and try again — a new passkey will be created.'
      : stage.code === 'pending-unknown'
        ? 'No pending addition matches this code. Check it character by character on the other device.'
        : stage.code === 'pending-consumed' || stage.code === 'pending-already-filled'
          ? 'This code was already used. Ask your other device for a fresh one.'
          : 'Something went wrong talking to the wallet service — this may be a connection problem; try again.';

  return (
    <FlowShell title="That didn't work">
      <div className="error" data-testid="manage-claim-error" data-code={stage.code ?? 'network'}>
        {explanation}
      </div>
      <p style={{ fontSize: 12 }}>{stage.message}</p>
      <div className="actions">
        <button onClick={onBack}>Back</button>
        <button className="primary" onClick={() => setStage({ step: 'input' })}>
          Try again
        </button>
      </div>
    </FlowShell>
  );
}
