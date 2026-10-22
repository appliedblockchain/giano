import { Alert, Button, Checkbox, Dialog, Field, Input, Portal, Stack, Text, Textarea } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import type { OperatorTenant } from '../lib/operator-api';
import { OriginsField } from './CreateTenantDialog';
import { useOperatorAction } from './LifecycleDialogs';
import { ApiErrorAlert, issuesByField, linesToList } from './shared';

type Form = {
  rpName: string;
  expectedOrigins: string;
  allowedDappOrigins: string;
  corsOrigins: string;
  openRegistration: boolean;
  policy: string;
  branding: string;
};

const toForm = (tenant: OperatorTenant): Form => ({
  rpName: tenant.rpName,
  // the wallet origin is always an expected origin, so it is not offered for removal here
  expectedOrigins: tenant.expectedOrigins.filter((origin) => origin !== tenant.walletOrigin).join('\n'),
  allowedDappOrigins: tenant.allowedDappOrigins.join('\n'),
  corsOrigins: tenant.corsOrigins.join('\n'),
  openRegistration: tenant.openRegistration,
  policy: JSON.stringify(tenant.policy, null, 2),
  branding: JSON.stringify(tenant.branding, null, 2),
});

const parseJson = (text: string): { ok: true; value: Record<string, unknown> } | { ok: false } => {
  try {
    const value = JSON.parse(text || '{}') as unknown;
    return value && typeof value === 'object' && !Array.isArray(value) ? { ok: true, value: value as Record<string, unknown> } : { ok: false };
  } catch {
    return { ok: false };
  }
};

/**
 * Edit a tenant's mutable fields (specs/OPERATOR-ADMIN-SPECS.md §11.3). Optimistic: the request
 * carries the version the form was opened at, and a 412 means someone changed the tenant since.
 * The drawer then reloads underneath while this form keeps what the operator typed, so it can be
 * re-applied against the new version rather than lost.
 */
export function EditTenantDialog({ open, onClose, tenant, onSaved, onConflict }: { open: boolean; onClose: () => void; tenant: OperatorTenant; onSaved: () => void; onConflict: () => void }) {
  const { act, busy, error, reset } = useOperatorAction();
  const [form, setForm] = useState<Form>(() => toForm(tenant));
  const [baseVersion, setBaseVersion] = useState(tenant.version);
  const [conflicted, setConflicted] = useState(false);
  const issues = issuesByField(error);
  const policy = parseJson(form.policy);
  const branding = parseJson(form.branding);

  // a fresh open starts from the tenant as it is now
  useEffect(() => {
    if (open && !conflicted) {
      setForm(toForm(tenant));
      setBaseVersion(tenant.version);
    }
  }, [open, tenant, conflicted]);

  const set = (field: keyof Form) => (event: { target: { value: string } }) => setForm({ ...form, [field]: event.target.value });

  const close = () => {
    setConflicted(false);
    reset();
    onClose();
  };

  const save = async () => {
    if (!policy.ok || !branding.ok) return;
    const result = await act((api) =>
      api.update(tenant.slug, baseVersion, {
        rpName: form.rpName.trim(),
        expectedOrigins: linesToList(form.expectedOrigins),
        allowedDappOrigins: linesToList(form.allowedDappOrigins),
        corsOrigins: linesToList(form.corsOrigins),
        openRegistration: form.openRegistration,
        policy: policy.value,
        branding: branding.value,
      }),
    );
    if (!result) return;
    if (result.ok) {
      setConflicted(false);
      onSaved();
      close();
    } else if (result.error.status === 412) {
      setConflicted(true);
      if (typeof result.error.version === 'number') setBaseVersion(result.error.version);
      onConflict();
    }
  };

  const fieldError = (name: string) => issues[name]?.join(' · ');

  return (
    <Dialog.Root open={open} onOpenChange={(event) => !event.open && close()} size="lg" scrollBehavior="inside">
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>Edit {tenant.slug}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Stack gap="4">
                {conflicted && (
                  <Alert.Root status="warning" size="sm">
                    <Alert.Indicator />
                    <Alert.Content>
                      <Alert.Title>Someone else changed this tenant</Alert.Title>
                      <Alert.Description>
                        The drawer now shows its current values. Your edits are kept below — check them against what changed, then save again to apply
                        them on top.
                      </Alert.Description>
                    </Alert.Content>
                  </Alert.Root>
                )}
                <Text fontSize="sm" color="fg.muted">
                  Slug, id, wallet origin ({tenant.walletOrigin}) and RP ID ({tenant.rpId}) cannot change: a tenant that needs a new origin is a new
                  tenant.
                </Text>
                <Field.Root required invalid={!!fieldError('rpName')}>
                  <Field.Label>Display name</Field.Label>
                  <Input value={form.rpName} onChange={set('rpName')} />
                  <Field.ErrorText>{fieldError('rpName')}</Field.ErrorText>
                </Field.Root>
                <OriginsField label="Expected origins" help="Extra ceremony origins; the wallet origin is always one." value={form.expectedOrigins} onChange={set('expectedOrigins')} error={fieldError('expectedOrigins')} />
                <OriginsField label="dApp origins" help="The dApps allowed to open this wallet." value={form.allowedDappOrigins} onChange={set('allowedDappOrigins')} error={fieldError('allowedDappOrigins')} />
                <OriginsField label="CORS origins" help="dApp origins that call wallet-api cross-origin." value={form.corsOrigins} onChange={set('corsOrigins')} error={fieldError('corsOrigins')} />
                <Checkbox.Root checked={form.openRegistration} onCheckedChange={(event) => setForm({ ...form, openRegistration: event.checked === true })}>
                  <Checkbox.HiddenInput />
                  <Checkbox.Control />
                  <Checkbox.Label>Open registration</Checkbox.Label>
                </Checkbox.Root>
                {fieldError('adminKeys') && <Text color="red.fg" fontSize="sm">{fieldError('adminKeys')}</Text>}
                <Field.Root invalid={!policy.ok || !!fieldError('policy')}>
                  <Field.Label>Policy (JSON)</Field.Label>
                  <Textarea value={form.policy} onChange={set('policy')} rows={4} fontFamily="mono" fontSize="sm" />
                  <Field.ErrorText>{!policy.ok ? 'Not a JSON object' : fieldError('policy')}</Field.ErrorText>
                  <Field.HelperText>Per-tenant overrides of the relay policy; checked by wallet-api on save.</Field.HelperText>
                </Field.Root>
                <Field.Root invalid={!branding.ok || !!fieldError('branding')}>
                  <Field.Label>Branding (JSON)</Field.Label>
                  <Textarea value={form.branding} onChange={set('branding')} rows={3} fontFamily="mono" fontSize="sm" />
                  <Field.ErrorText>{!branding.ok ? 'Not a JSON object' : fieldError('branding')}</Field.ErrorText>
                  <Field.HelperText>Stored, but not yet read by any wallet UI — changing it changes nothing on screen (O-7).</Field.HelperText>
                </Field.Root>
                {error && !error.issues && error.status !== 412 && <ApiErrorAlert error={error} />}
              </Stack>
            </Dialog.Body>
            <Dialog.Footer>
              <Button variant="ghost" onClick={close} disabled={busy}>
                Cancel
              </Button>
              <Button colorPalette="brand" onClick={() => void save()} loading={busy} disabled={!policy.ok || !branding.ok || !form.rpName.trim()}>
                Save
              </Button>
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  );
}
