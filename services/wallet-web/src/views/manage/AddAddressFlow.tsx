import { encodeAddOwnerAddress } from '@appliedblockchain/giano-wallet-core';
import { useEffect, useRef, useState } from 'react';
import { getAddress, isAddress } from 'viem';
import type { SponsorshipPreflight } from '../../wallet';
import { applyOwnerChange, type ChainProgress, type OwnerChangeOutcome } from './ops';
import { ChainProgressList, ChainsNotice, FlowShell, RefusalNotice, manageLog, preflightManagement, type FlowProps } from './shared';

/**
 * Adding an externally-owned account as an owner (WM-24…WM-26, BR-15). The address is
 * checksum-validated, shown in full and unabbreviated, and confirmed explicitly — in a
 * step separate from any passkey prompt — with a plain statement of what is granted.
 */
export function AddAddressFlow({ api, runtimes, me, onDone }: FlowProps) {
  type Stage =
    | { step: 'preflight' }
    | { step: 'refused'; refusal: Extract<SponsorshipPreflight, { state: 'refused' }> }
    | { step: 'input' }
    | { step: 'consent'; address: `0x${string}` }
    | { step: 'running' }
    | { step: 'done'; outcome: OwnerChangeOutcome }
    | { step: 'error'; message: string };

  const [stage, setStage] = useState<Stage>({ step: 'preflight' });
  const [input, setInput] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);
  const [understood, setUnderstood] = useState(false);
  const [progress, setProgress] = useState<ChainProgress[]>([]);
  const started = useRef(false);

  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void (async () => {
      const preflight = await preflightManagement(runtime, me.walletAddress);
      if (preflight.state === 'refused') {
        manageLog('add-address: sponsorship refused before consent', preflight);
        setStage({ step: 'refused', refusal: preflight });
      } else {
        setStage({ step: 'input' });
      }
    })();
  }, [me, runtime]);

  const validate = () => {
    const value = input.trim();
    // WM-25: EIP-55 checksum correctness. viem's isAddress rejects a wrong mixed-case
    // checksum; an all-lowercase address carries no checksum to validate and is refused
    // here so the user pastes the checksummed form their wallet displays.
    if (!isAddress(value)) {
      setInputError('Not a valid Ethereum address (check the EIP-55 checksum).');
      return;
    }
    if (value !== getAddress(value)) {
      setInputError('Enter the address in its checksummed (mixed-case) form, exactly as your wallet shows it.');
      return;
    }
    if (value.toLowerCase() === me.walletAddress.toLowerCase()) {
      setInputError('That is this wallet’s own address.');
      return;
    }
    setInputError(null);
    setUnderstood(false);
    setStage({ step: 'consent', address: value });
  };

  const approve = async (address: `0x${string}`) => {
    setStage({ step: 'running' });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: me.walletAddress,
      label: 'add-address',
      buildData: async () => encodeAddOwnerAddress(address),
      onProgress: setProgress,
    });
    if (outcome.appliedChainIds.length > 0) {
      // The registry has no row for an address owner; the audit trail still records the
      // change and who authorised it (WM-50).
      await api
        .recordOwnerEvent({ action: 'owner-added', ownerKind: 'address', owner: address, chainIds: outcome.appliedChainIds })
        .catch((error) => manageLog('add-address: audit write failed', (error as Error).message));
    }
    setStage({ step: 'done', outcome });
  };

  if (stage.step === 'preflight') {
    return (
      <FlowShell title="Add an Ethereum account">
        <p>
          <span className="spinner" /> Checking that this change is covered…
        </p>
      </FlowShell>
    );
  }

  if (stage.step === 'refused') {
    return (
      <>
        <RefusalNotice refusal={stage.refusal} />
        <div className="actions">
          <button onClick={() => void onDone(false)}>Back</button>
        </div>
      </>
    );
  }

  if (stage.step === 'input') {
    return (
      <FlowShell title="Add an Ethereum account">
        <p>A software or hardware wallet you already hold can act on this wallet as an owner.</p>
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="0x… (checksummed address)"
          style={{ width: '100%', borderRadius: 8, border: '1px solid var(--border)', padding: '10px', background: 'var(--bg)', color: 'var(--fg)', fontFamily: 'ui-monospace, monospace' }}
          data-testid="manage-address-input"
        />
        {inputError ? <div className="error" data-testid="manage-address-error">{inputError}</div> : null}
        <div className="actions">
          <button onClick={() => void onDone(false)}>Cancel</button>
          <button className="primary" onClick={validate} disabled={!input.trim()} data-testid="manage-address-continue">
            Continue
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'consent') {
    return (
      <FlowShell title="Review: add this account">
        {/* WM-25: full and unabbreviated. */}
        <div className="data-box" style={{ fontSize: 14, textAlign: 'center' }} data-testid="manage-address-full">
          {stage.address}
        </div>
        {/* WM-26: what is granted, plainly. */}
        <p data-testid="manage-address-grant-note">
          This account gains <b>full and equal control</b> of your wallet — no threshold, no limit. It can also act{' '}
          <b>directly on-chain</b>, outside the app's relay: those transactions are not covered by the relay's policy
          checks or its audit trail, and it pays its own gas for them.
        </p>
        <label style={{ display: 'flex', gap: 8, fontSize: 13, alignItems: 'flex-start' }}>
          <input type="checkbox" checked={understood} onChange={(event) => setUnderstood(event.target.checked)} data-testid="manage-address-understood" />
          <span>I checked the address character by character and I understand what it is being granted.</span>
        </label>
        <ChainsNotice runtimes={runtimes} />
        <div className="actions">
          <button onClick={() => setStage({ step: 'input' })}>Back</button>
          <button className="primary" onClick={() => void approve(stage.address)} disabled={!understood} data-testid="manage-address-approve">
            Add account
          </button>
        </div>
      </FlowShell>
    );
  }

  if (stage.step === 'running') {
    return (
      <FlowShell title="Adding the account…">
        <p>Confirm each network's passkey prompt. Progress per network:</p>
        <ChainProgressList progress={progress} />
      </FlowShell>
    );
  }

  if (stage.step === 'done') {
    const { outcome } = stage;
    return (
      <FlowShell title={outcome.ok ? 'Account added' : outcome.appliedChainIds.length > 0 ? 'Account added — attention needed' : 'Nothing was added'}>
        {outcome.refusal ? <RefusalNotice refusal={outcome.refusal} /> : null}
        <ChainProgressList progress={outcome.progress} />
        <div className="actions">
          <button className="primary" onClick={() => void onDone(true)} data-testid="manage-flow-done">
            Back to the list
          </button>
        </div>
      </FlowShell>
    );
  }

  return (
    <FlowShell title="Something went wrong">
      <div className="error" data-testid="manage-flow-error">{stage.message}</div>
      <div className="actions">
        <button onClick={() => void onDone(false)}>Back</button>
      </div>
    </FlowShell>
  );
}
