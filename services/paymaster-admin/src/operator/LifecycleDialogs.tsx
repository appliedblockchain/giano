import type { GianoPaymasterClient } from '@appliedblockchain/giano-paymaster-sdk';
import { Alert, Button, Dialog, Field, Input, Portal, Stack, Text, Textarea } from '@chakra-ui/react';
import { useState, type ReactNode } from 'react';
import { Copyable } from '../components/ui';
import { useWrite } from '../hooks/useWrite';
import type { ApiError, ApiResult, IssuedAdminKey, OperatorApi, OperatorTenant } from '../lib/operator-api';
import { useOperator } from '../lib/operator-session';
import { ApiErrorAlert, OnChainStep, type OnChainState } from './shared';

/**
 * The lifecycle and key actions of the tenant drawer (specs/OPERATOR-ADMIN-SPECS.md §11.3). Each is
 * one operator API call; where the chain has a matching switch, the dialog offers it as a second,
 * optional step once the API call has succeeded — never instead of it, and never undoing it.
 */

type Base = { open: boolean; onClose: () => void; onDone: () => void; tenant: OperatorTenant };
type ChainBase = Base & {
  client: GianoPaymasterClient | undefined;
  canAdminister: boolean;
  onChain: OnChainState;
  refreshChain: () => Promise<void>;
};

/** A dialog that runs one operator call and shows its refusal in place. */
function ActionDialog({
  open,
  onClose,
  title,
  children,
  confirmLabel,
  confirmPalette = 'brand',
  disabled,
  busy,
  error,
  onConfirm,
  after,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  confirmPalette?: string;
  disabled?: boolean;
  busy: boolean;
  error?: ApiError;
  onConfirm: () => void;
  /**
   * Shown instead of the form once the call succeeded: the optional on-chain step, or the key.
   * Callers pass `done && <…/>`, so anything falsy means "not yet".
   */
  after?: ReactNode;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={(event) => !event.open && onClose()}>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>{title}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Stack gap="4">
                {after || children}
                {error && <ApiErrorAlert error={error} />}
              </Stack>
            </Dialog.Body>
            <Dialog.Footer>
              {after ? (
                <Button onClick={onClose}>Done</Button>
              ) : (
                <>
                  <Button variant="ghost" onClick={onClose} disabled={busy}>
                    Cancel
                  </Button>
                  <Button colorPalette={confirmPalette} onClick={onConfirm} loading={busy} disabled={disabled}>
                    {confirmLabel}
                  </Button>
                </>
              )}
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  );
}

/**
 * Runs an operator call and keeps its refusal for the dialog. Resolves to the result, or to
 * undefined when the session ended under it (the area is then back on sign-in).
 */
export function useOperatorAction() {
  const { run } = useOperator();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError>();
  const act = async <T,>(call: (api: OperatorApi) => Promise<ApiResult<T>>): Promise<ApiResult<T> | undefined> => {
    setBusy(true);
    setError(undefined);
    try {
      const result = await run(call);
      if (result && !result.ok) setError(result.error);
      return result;
    } finally {
      setBusy(false);
    }
  };
  return { act, busy, error, reset: () => setError(undefined) };
}

export function SuspendDialog({ open, onClose, onDone, tenant, client, canAdminister, onChain, refreshChain }: ChainBase) {
  const { act, busy, error } = useOperatorAction();
  const write = useWrite(refreshChain);
  const [reason, setReason] = useState('');
  const [suspended, setSuspended] = useState(false);

  const confirm = async () => {
    if ((await act((api) => api.suspend(tenant.slug, reason.trim())))?.ok) {
      setSuspended(true);
      onDone();
    }
  };

  return (
    <ActionDialog
      open={open}
      onClose={onClose}
      title={`Suspend ${tenant.slug}`}
      confirmLabel="Suspend"
      confirmPalette="orange"
      disabled={!reason.trim()}
      busy={busy}
      error={error}
      onConfirm={() => void confirm()}
      after={
        suspended && (
          <Stack gap="3">
            <Text>
              <b>{tenant.slug}</b> is suspended: from the next request it resolves nowhere, as if it did not exist. Tell the tenant — its users see
              the same failure an unknown tenant gets.
            </Text>
            {onChain === 'enabled' ? (
              <OnChainStep
                title="Also disable it on the paymaster"
                description="An authorisation signed just before the suspension stays valid on-chain until it expires. Disabling the tenant on the paymaster closes that window now."
                allowed={canAdminister && client !== undefined}
                busy={write.busy}
                actionLabel="Disable on-chain"
                onAct={() => client && void write.run(`Disable ${tenant.slug}`, () => client.setTenantEnabled(tenant.id, false))}
              />
            ) : (
              <Text fontSize="sm" color="fg.muted">
                It is not enabled on this paymaster, so there is nothing to disable on-chain.
              </Text>
            )}
          </Stack>
        )
      }
    >
      <Text>Suspending stops this tenant resolving on every replica from the next request. Its users, keys and sessions are kept, and resume restores them.</Text>
      <Field.Root required>
        <Field.Label>Reason</Field.Label>
        <Textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Recorded in the tenant's history" autoFocus />
      </Field.Root>
    </ActionDialog>
  );
}

export function ResumeDialog({ open, onClose, onDone, tenant, client, canAdminister, onChain, refreshChain }: ChainBase) {
  const { act, busy, error } = useOperatorAction();
  const write = useWrite(refreshChain);
  const [resumed, setResumed] = useState(false);

  const confirm = async () => {
    if ((await act((api) => api.resume(tenant.slug)))?.ok) {
      setResumed(true);
      onDone();
    }
  };

  return (
    <ActionDialog
      open={open}
      onClose={onClose}
      title={`Resume ${tenant.slug}`}
      confirmLabel="Resume"
      busy={busy}
      error={error}
      onConfirm={() => void confirm()}
      after={
        resumed && (
          <Stack gap="3">
            <Text>
              <b>{tenant.slug}</b> is active again; sessions issued before the suspension work if they have not expired.
            </Text>
            {onChain === 'disabled' && (
              <OnChainStep
                title="Re-enable it on the paymaster"
                description="It is disabled on this paymaster, so nothing it does is sponsored until it is enabled again."
                allowed={canAdminister && client !== undefined}
                busy={write.busy}
                actionLabel="Enable on-chain"
                onAct={() => client && void write.run(`Enable ${tenant.slug}`, () => client.setTenantEnabled(tenant.id, true))}
              />
            )}
          </Stack>
        )
      }
    >
      <Text>The tenant resolves again from the next request.</Text>
    </ActionDialog>
  );
}

export function DeleteDialog({ open, onClose, onDone, tenant }: Base) {
  const { act, busy, error } = useOperatorAction();
  const [typed, setTyped] = useState('');

  const confirm = async () => {
    if ((await act((api) => api.remove(tenant.slug)))?.ok) {
      onDone();
      onClose();
    }
  };

  return (
    <ActionDialog
      open={open}
      onClose={onClose}
      title={`Delete ${tenant.slug}`}
      confirmLabel="Delete permanently"
      confirmPalette="red"
      disabled={typed !== tenant.slug}
      busy={busy}
      error={error}
      onConfirm={() => void confirm()}
    >
      <DeleteBody tenant={tenant} typed={typed} setTyped={setTyped} />
    </ActionDialog>
  );
}

function DeleteBody({ tenant, typed, setTyped }: { tenant: OperatorTenant; typed: string; setTyped: (value: string) => void }) {
  return (
    <Stack gap="3">
      <Alert.Root status="warning" size="sm">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Description>
            Deleting cannot be undone. The slug <b>{tenant.slug}</b>, the wallet origin <b>{tenant.walletOrigin}</b> and the RP ID <b>{tenant.rpId}</b>{' '}
            can never be used again: passkeys users still hold are bound to that RP ID. Its users and records are kept; its sessions and admin keys
            are removed.
          </Alert.Description>
        </Alert.Content>
      </Alert.Root>
      <Field.Root>
        <Field.Label>Type the slug to confirm</Field.Label>
        <Input value={typed} onChange={(event) => setTyped(event.target.value)} placeholder={tenant.slug} autoComplete="off" />
      </Field.Root>
    </Stack>
  );
}

export function IssueKeyDialog({ open, onClose, onDone, tenant }: Base) {
  const { act, busy, error } = useOperatorAction();
  const [label, setLabel] = useState('');
  const [issued, setIssued] = useState<IssuedAdminKey>();
  const confirm = async () => {
    const result = await act((api) => api.issueKey(tenant.slug, label.trim()));
    if (result?.ok) {
      setIssued(result.value);
      onDone();
    }
  };
  return (
    <ActionDialog
      open={open}
      onClose={onClose}
      title={`Issue an admin key for ${tenant.slug}`}
      confirmLabel="Issue key"
      disabled={!label.trim()}
      busy={busy}
      error={error}
      onConfirm={() => void confirm()}
      after={issued && <ShownOnce keys={[issued]} />}
    >
      <Field.Root required>
        <Field.Label>Label</Field.Label>
        <Input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="acme-backend" autoFocus />
        <Field.HelperText>What the key is for. The key itself is generated by the server.</Field.HelperText>
      </Field.Root>
    </ActionDialog>
  );
}

export function RevokeKeyDialog({ open, onClose, onDone, tenant, keyId, keyLabel }: Base & { keyId: string; keyLabel: string }) {
  const { act, busy, error } = useOperatorAction();
  const confirm = async () => {
    if ((await act((api) => api.revokeKey(tenant.slug, keyId)))?.ok) {
      onDone();
      onClose();
    }
  };
  return (
    <ActionDialog
      open={open}
      onClose={onClose}
      title={`Revoke admin key “${keyLabel}”`}
      confirmLabel="Revoke"
      confirmPalette="red"
      busy={busy}
      error={error}
      onConfirm={() => void confirm()}
    >
      <Text>Anything still using this key is refused from the next request. The tenant's other keys are unaffected.</Text>
    </ActionDialog>
  );
}

/** Generated admin keys, shown the one time the API returns them. */
export function ShownOnce({ keys }: { keys: IssuedAdminKey[] }) {
  return (
    <Stack gap="3">
      <Alert.Root status="warning" size="sm">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>These are shown once</Alert.Title>
          <Alert.Description>Copy each key now and hand it to the tenant. Only a hash is stored, so they cannot be shown again.</Alert.Description>
        </Alert.Content>
      </Alert.Root>
      {keys.map((key) => (
        <Stack key={key.id} gap="1">
          <Text fontSize="xs" color="fg.muted">
            {key.label}
          </Text>
          <Copyable value={key.key} label={`Admin key ${key.label}`} />
        </Stack>
      ))}
    </Stack>
  );
}
