import { Alert, Button, Checkbox, Dialog, Field, Input, Portal, Stack, Text, Textarea } from '@chakra-ui/react';
import { useState } from 'react';
import type { Address } from 'viem';
import { useWrite } from '../hooks/useWrite';
import type { IssuedAdminKey, PlatformTenant } from '../lib/platform-api';
import { ShownOnce, usePlatformAction } from './LifecycleDialogs';
import type { PlatformAreaProps } from './PlatformArea';
import { ApiErrorAlert, canAdministerOnChain, issuesByField, linesToList, OnChainStep } from './shared';

const EMPTY = { slug: '', walletOrigin: '', rpName: '', expectedOrigins: '', allowedDappOrigins: '', corsOrigins: '', openRegistration: false, keyLabels: 'backend', id: '' };

/**
 * Create a tenant (specs/PLATFORM-ADMIN-SPECS.md §11.3): the form, then the generated admin keys
 * shown once, then — optionally — registering it on this deployment's paymaster.
 *
 * The form validates nothing itself. wallet-api is the one place the tenant invariants live, and a
 * second copy here would drift from it; its 400 names each violated field, and the form shows the
 * message against that field.
 */
export function CreateTenantDialog({ open, onClose, onCreated, deployment, client, myRoles, refreshChain }: PlatformAreaProps & { open: boolean; onClose: () => void; onCreated: () => void }) {
  const { act, busy, error, reset } = usePlatformAction();
  const write = useWrite(refreshChain);
  const [form, setForm] = useState(EMPTY);
  const [created, setCreated] = useState<{ tenant: PlatformTenant; adminKeys: IssuedAdminKey[] }>();
  const [withdrawAddress, setWithdrawAddress] = useState('');
  const [registered, setRegistered] = useState(false);
  const issues = issuesByField(error);
  const set = (field: keyof typeof EMPTY) => (event: { target: { value: string } }) => setForm({ ...form, [field]: event.target.value });

  const close = () => {
    setForm(EMPTY);
    setCreated(undefined);
    setWithdrawAddress('');
    setRegistered(false);
    reset();
    onClose();
  };

  const submit = async () => {
    const result = await act((api) =>
      api.create({
        slug: form.slug.trim(),
        walletOrigin: form.walletOrigin.trim(),
        rpName: form.rpName.trim(),
        expectedOrigins: linesToList(form.expectedOrigins),
        allowedDappOrigins: linesToList(form.allowedDappOrigins),
        corsOrigins: linesToList(form.corsOrigins),
        openRegistration: form.openRegistration,
        adminKeys: linesToList(form.keyLabels).map((label) => ({ label })),
        ...(form.id.trim() ? { id: form.id.trim() } : {}),
      }),
    );
    if (result?.ok) {
      setCreated(result.value);
      onCreated();
    }
  };

  const register = async () => {
    if (!client || !created) return;
    const done = await write.run(`Register ${created.tenant.slug}`, () => client.registerTenant(created.tenant.id, withdrawAddress as Address, created.tenant.slug));
    if (done) setRegistered(true);
  };

  const fieldError = (name: string) => issues[name]?.join(' · ');

  return (
    <Dialog.Root open={open} onOpenChange={(event) => !event.open && close()} size="lg" scrollBehavior="inside">
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>{created ? `Created ${created.tenant.slug}` : 'Create a tenant'}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              {created ? (
                <Stack gap="4">
                  <Text>
                    <b>{created.tenant.slug}</b> exists in wallet-api now and resolves on its wallet origin from the next request — nothing was
                    redeployed.
                  </Text>
                  {created.adminKeys.length > 0 && <ShownOnce keys={created.adminKeys} />}
                  {registered ? (
                    <Text color="green.fg">Registered on {deployment.name}.</Text>
                  ) : (
                    <OnChainStep
                      title={`Register on ${deployment.name}`}
                      description="Optional. Registers this tenant's id on the paymaster so it can be funded and sponsored. Registration is once-only."
                      allowed={canAdministerOnChain(myRoles) && client !== undefined && /^0x[0-9a-fA-F]{40}$/.test(withdrawAddress)}
                      busy={write.busy}
                      actionLabel="Register on-chain"
                      onAct={() => void register()}
                    >
                      <Field.Root>
                        <Field.Label>Withdrawal address</Field.Label>
                        <Input value={withdrawAddress} onChange={(event) => setWithdrawAddress(event.target.value)} placeholder="0x…" />
                        <Field.HelperText>The only address that will ever be able to withdraw this tenant's balance.</Field.HelperText>
                      </Field.Root>
                    </OnChainStep>
                  )}
                  <Alert.Root status="info" size="sm">
                    <Alert.Indicator />
                    <Alert.Content>
                      <Alert.Title>Still to do outside this console</Alert.Title>
                      <Alert.Description>
                        Serve the wallet origin {created.tenant.walletOrigin}: DNS, a certificate and a wallet UI are infrastructure work. And the
                        tenant has no sponsorship rules until one of the keys above is used to set them (PUT /v1/admin/sponsorship).
                      </Alert.Description>
                    </Alert.Content>
                  </Alert.Root>
                </Stack>
              ) : (
                <Stack gap="4">
                  <Field.Root required invalid={!!fieldError('slug')}>
                    <Field.Label>Slug</Field.Label>
                    <Input value={form.slug} onChange={set('slug')} placeholder="acme" autoFocus />
                    <Field.ErrorText>{fieldError('slug')}</Field.ErrorText>
                    <Field.HelperText>Lowercase, digits and dashes. Never reusable once the tenant is deleted.</Field.HelperText>
                  </Field.Root>
                  <Field.Root required invalid={!!fieldError('walletOrigin') || !!fieldError('rpId')}>
                    <Field.Label>Wallet origin</Field.Label>
                    <Input value={form.walletOrigin} onChange={set('walletOrigin')} placeholder="https://wallet.acme.app" />
                    <Field.ErrorText>{fieldError('walletOrigin') ?? fieldError('rpId')}</Field.ErrorText>
                    <Field.HelperText>Its host becomes the tenant's RP ID, which passkeys bind to irreversibly.</Field.HelperText>
                  </Field.Root>
                  <Field.Root required invalid={!!fieldError('rpName')}>
                    <Field.Label>Display name</Field.Label>
                    <Input value={form.rpName} onChange={set('rpName')} placeholder="Acme Wallet" />
                    <Field.ErrorText>{fieldError('rpName')}</Field.ErrorText>
                  </Field.Root>
                  <OriginsField label="Expected origins" help="Extra ceremony origins, one per line; each must be the wallet host or under it." value={form.expectedOrigins} onChange={set('expectedOrigins')} error={fieldError('expectedOrigins')} />
                  <OriginsField label="dApp origins" help="The dApps allowed to open this wallet, one per line." value={form.allowedDappOrigins} onChange={set('allowedDappOrigins')} error={fieldError('allowedDappOrigins')} />
                  <OriginsField label="CORS origins" help="dApp origins that call wallet-api cross-origin, one per line." value={form.corsOrigins} onChange={set('corsOrigins')} error={fieldError('corsOrigins')} />
                  <Checkbox.Root checked={form.openRegistration} onCheckedChange={(event) => setForm({ ...form, openRegistration: event.checked === true })}>
                    <Checkbox.HiddenInput />
                    <Checkbox.Control />
                    <Checkbox.Label>Open registration (anyone on the wallet origin may create a wallet)</Checkbox.Label>
                  </Checkbox.Root>
                  <Field.Root invalid={!!fieldError('adminKeys')}>
                    <Field.Label>Admin keys to generate</Field.Label>
                    <Textarea value={form.keyLabels} onChange={set('keyLabels')} rows={2} placeholder="one label per line" />
                    <Field.ErrorText>{fieldError('adminKeys')}</Field.ErrorText>
                    <Field.HelperText>One label per line. Required when registration is closed. Keys are generated by the server and shown once.</Field.HelperText>
                  </Field.Root>
                  <Field.Root invalid={!!fieldError('id')}>
                    <Field.Label>Fixed id (optional)</Field.Label>
                    <Input value={form.id} onChange={set('id')} placeholder="UUID of a tenant already registered on-chain" />
                    <Field.ErrorText>{fieldError('id')}</Field.ErrorText>
                  </Field.Root>
                  {error && !error.issues && <ApiErrorAlert error={error} />}
                  {error?.issues && issues['(form)'] && <ApiErrorAlert error={error} />}
                </Stack>
              )}
            </Dialog.Body>
            <Dialog.Footer>
              {created ? (
                <Button onClick={close}>Done</Button>
              ) : (
                <>
                  <Button variant="ghost" onClick={close} disabled={busy}>
                    Cancel
                  </Button>
                  <Button colorPalette="brand" onClick={() => void submit()} loading={busy} disabled={!form.slug || !form.walletOrigin || !form.rpName}>
                    Create tenant
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

export function OriginsField({ label, help, value, onChange, error }: { label: string; help: string; value: string; onChange: (event: { target: { value: string } }) => void; error?: string }) {
  return (
    <Field.Root invalid={!!error}>
      <Field.Label>{label}</Field.Label>
      <Textarea value={value} onChange={onChange} rows={2} placeholder="https://…" fontFamily="mono" fontSize="sm" />
      <Field.ErrorText>{error}</Field.ErrorText>
      <Field.HelperText>{help}</Field.HelperText>
    </Field.Root>
  );
}
