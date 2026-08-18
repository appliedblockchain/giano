import type { GianoPaymasterClient, PaymasterRoleName, TenantView } from '@appliedblockchain/giano-paymaster-sdk';
import { Alert, Button, Dialog, Field, HStack, Input, Portal, Stack, Table, Text } from '@chakra-ui/react';
import { useState } from 'react';
import { LuPlus, LuWallet } from 'react-icons/lu';
import { parseEther, type Address } from 'viem';
import { Copyable, SectionCard, TenantStatusBadge } from '../components/ui';
import { useWrite } from '../hooks/useWrite';
import { eth, exactEth } from '../lib/format';

type Props = {
  client: GianoPaymasterClient;
  tenants: readonly TenantView[];
  myRoles: readonly PaymasterRoleName[];
  connected: boolean;
  /** False when the roster came from registration logs rather than the on-chain set. */
  rosterOnChain: boolean;
  refresh: () => Promise<void>;
};

/**
 * The tenant roster and the operations on it.
 *
 * On an upgraded paymaster this is a single on-chain read, because the roster is an enumerable
 * set — no backend, and the balances are the chain's own rather than a cached projection. On a
 * proxy that predates the roster the SDK falls back to a log scan, which is a weaker guarantee and
 * says so on screen rather than quietly presenting a possibly-incomplete list as complete.
 *
 * Funding is offered to everyone — anyone may fund a tenant — while the administrative actions are
 * gated on TENANT_ADMIN_ROLE, and withdrawal is offered to nobody here at all, because only the
 * tenant's own registered address can perform it.
 */
export function TenantsPanel({ client, tenants, myRoles, connected, rosterOnChain, refresh }: Props) {
  const { run, busy } = useWrite(refresh);
  const canAdminister = myRoles.includes('TENANT_ADMIN_ROLE');
  const canSetFees = myRoles.includes('FEE_ADMIN_ROLE');

  const [funding, setFunding] = useState<TenantView>();
  const [registering, setRegistering] = useState(false);

  return (
    <>
      <SectionCard
        title={`Tenants (${tenants.length})`}
        subtitle={
          rosterOnChain
            ? 'Enumerated directly from the chain — the slug comes from the registration event, which is the one field not stored on-chain'
            : 'Reconstructed from registration events: this paymaster predates the on-chain roster'
        }
        action={
          canAdminister && (
            <Button size="sm" colorPalette="brand" onClick={() => setRegistering(true)} disabled={busy}>
              <LuPlus /> Register tenant
            </Button>
          )
        }
      >
        {!rosterOnChain && (
          <Alert.Root status="info" mb="3" size="sm">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Description>
                This list came from a log scan, because the proxy has not been upgraded to the version that keeps the roster on-chain. A tenant whose
                registration has fallen outside the node's retained log history would be missing from it.
              </Alert.Description>
            </Alert.Content>
          </Alert.Root>
        )}

        {tenants.length === 0 ? (
          <Text color="fg.muted">
            No tenants registered. A deployment is not complete until at least one is registered and funded.
          </Text>
        ) : (
          <Table.ScrollArea borderWidth="1px" rounded="md">
            <Table.Root size="sm" stickyHeader interactive>
              <Table.Header>
                <Table.Row>
                  <Table.ColumnHeader>Tenant</Table.ColumnHeader>
                  <Table.ColumnHeader>Status</Table.ColumnHeader>
                  <Table.ColumnHeader textAlign="end">Balance</Table.ColumnHeader>
                  <Table.ColumnHeader textAlign="end">Deficit</Table.ColumnHeader>
                  <Table.ColumnHeader textAlign="end">Fee</Table.ColumnHeader>
                  <Table.ColumnHeader>Withdraws to</Table.ColumnHeader>
                  <Table.ColumnHeader textAlign="end">Actions</Table.ColumnHeader>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {tenants.map((tenant) => (
                  <Table.Row key={tenant.id}>
                    <Table.Cell>
                      <Stack gap="0.5">
                        <Text fontWeight="medium">{tenant.slug ?? '(no slug)'}</Text>
                        <Copyable value={tenant.uuid} label="Tenant id" />
                      </Stack>
                    </Table.Cell>
                    <Table.Cell>
                      <TenantStatusBadge status={tenant.status} />
                    </Table.Cell>
                    <Table.Cell textAlign="end" fontFamily="mono" title={exactEth(tenant.balance)}>
                      {eth(tenant.balance)}
                    </Table.Cell>
                    <Table.Cell
                      textAlign="end"
                      fontFamily="mono"
                      color={tenant.deficit > 0n ? 'red.fg' : 'fg.muted'}
                      title={exactEth(tenant.deficit)}
                    >
                      {eth(tenant.deficit)}
                    </Table.Cell>
                    <Table.Cell textAlign="end" fontFamily="mono" title={exactEth(tenant.effectiveFeeWei)}>
                      {eth(tenant.effectiveFeeWei, 6)}
                      {tenant.hasFeeOverride && (
                        <Text as="span" fontSize="xs" color="brand.fg" ml="1">
                          override
                        </Text>
                      )}
                    </Table.Cell>
                    <Table.Cell>
                      <Copyable value={tenant.withdrawAddress} label="Withdrawal address" />
                    </Table.Cell>
                    <Table.Cell textAlign="end">
                      <HStack gap="1" justify="flex-end">
                        <Button size="xs" variant="outline" onClick={() => setFunding(tenant)} disabled={!connected || busy}>
                          Fund
                        </Button>
                        {canAdminister && (
                          <Button
                            size="xs"
                            variant="outline"
                            colorPalette={tenant.enabled ? 'orange' : 'green'}
                            disabled={busy}
                            onClick={() =>
                              void run(`${tenant.enabled ? 'Disable' : 'Enable'} ${tenant.slug ?? tenant.uuid}`, () =>
                                client.setTenantEnabled(tenant.id, !tenant.enabled),
                              )
                            }
                          >
                            {tenant.enabled ? 'Disable' : 'Enable'}
                          </Button>
                        )}
                        {canSetFees && tenant.hasFeeOverride && (
                          <Button
                            size="xs"
                            variant="ghost"
                            disabled={busy}
                            onClick={() => void run(`Clear fee override on ${tenant.slug ?? tenant.uuid}`, () => client.setTenantFee(tenant.id, false, 0n))}
                          >
                            Clear fee
                          </Button>
                        )}
                      </HStack>
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table.Root>
          </Table.ScrollArea>
        )}

        <Text fontSize="xs" color="fg.muted" mt="3">
          Withdrawing a tenant balance is deliberately absent from this console: only a tenant's own registered withdrawal address can do it, and no
          role on the paymaster — including the one you may be holding — can reach those funds.
        </Text>
      </SectionCard>

      <FundDialog tenant={funding} client={client} onClose={() => setFunding(undefined)} refresh={refresh} />
      <RegisterDialog open={registering} client={client} onClose={() => setRegistering(false)} refresh={refresh} />
    </>
  );
}

function FundDialog({
  tenant,
  client,
  onClose,
  refresh,
}: {
  tenant: TenantView | undefined;
  client: GianoPaymasterClient;
  onClose: () => void;
  refresh: () => Promise<void>;
}) {
  const { run, busy } = useWrite(refresh);
  const [amount, setAmount] = useState('0.1');

  const submit = async () => {
    let wei: bigint;
    try {
      wei = parseEther(amount);
    } catch {
      return;
    }
    if (!tenant) return;
    const done = await run(`Fund ${tenant.slug ?? tenant.uuid}`, () => client.depositFor(tenant.id, wei));
    if (done) onClose();
  };

  return (
    <Dialog.Root open={tenant !== undefined} onOpenChange={(event) => !event.open && onClose()}>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>Fund {tenant?.slug ?? tenant?.uuid}</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Stack gap="4">
                <Field.Root>
                  <Field.Label>Amount (ETH)</Field.Label>
                  <Input value={amount} onChange={(event) => setAmount(event.target.value)} inputMode="decimal" autoFocus />
                </Field.Root>
                {tenant && tenant.deficit > 0n && (
                  <Text fontSize="sm" color="orange.fg">
                    This tenant carries a {exactEth(tenant.deficit)} deficit. Funding clears the deficit first and credits only the remainder to the
                    spendable balance.
                  </Text>
                )}
                <Text fontSize="sm" color="fg.muted">
                  Funding is open to anyone — the tenant, the platform, or a finance system. It is also the only way funds enter the contract: a bare
                  transfer reverts, because money arriving without a tenant could never be attributed.
                </Text>
              </Stack>
            </Dialog.Body>
            <Dialog.Footer>
              <Button variant="ghost" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <Button colorPalette="brand" onClick={() => void submit()} loading={busy} loadingText="Funding">
                <LuWallet /> Fund
              </Button>
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  );
}

function RegisterDialog({
  open,
  client,
  onClose,
  refresh,
}: {
  open: boolean;
  client: GianoPaymasterClient;
  onClose: () => void;
  refresh: () => Promise<void>;
}) {
  const { run, busy } = useWrite(refresh);
  const [tenantId, setTenantId] = useState('');
  const [withdrawAddress, setWithdrawAddress] = useState('');
  const [slug, setSlug] = useState('');

  const submit = async () => {
    const done = await run(`Register ${slug || tenantId}`, () => client.registerTenant(tenantId, withdrawAddress as Address, slug));
    if (done) {
      setTenantId('');
      setWithdrawAddress('');
      setSlug('');
      onClose();
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={(event) => !event.open && onClose()}>
      <Portal>
        <Dialog.Backdrop />
        <Dialog.Positioner>
          <Dialog.Content>
            <Dialog.Header>
              <Dialog.Title>Register a tenant</Dialog.Title>
            </Dialog.Header>
            <Dialog.Body>
              <Stack gap="4">
                <Field.Root>
                  <Field.Label>Tenant id</Field.Label>
                  <Input value={tenantId} onChange={(event) => setTenantId(event.target.value)} placeholder="UUID, or a 16-byte hex id" autoFocus />
                  <Field.HelperText>The backend's tenant UUID is used directly, so there is no second identifier to keep in step.</Field.HelperText>
                </Field.Root>
                <Field.Root>
                  <Field.Label>Withdrawal address</Field.Label>
                  <Input value={withdrawAddress} onChange={(event) => setWithdrawAddress(event.target.value)} placeholder="0x…" />
                  <Field.HelperText>The only address that will ever be able to withdraw this tenant's balance.</Field.HelperText>
                </Field.Root>
                <Field.Root>
                  <Field.Label>Slug</Field.Label>
                  <Input value={slug} onChange={(event) => setSlug(event.target.value)} placeholder="acme-corp" />
                  <Field.HelperText>Emitted for reconciliation against the backend, not stored on-chain.</Field.HelperText>
                </Field.Root>
                <Text fontSize="sm" color="fg.muted">
                  Registration is once-only and there is no de-registration — the roster only ever grows.
                </Text>
              </Stack>
            </Dialog.Body>
            <Dialog.Footer>
              <Button variant="ghost" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <Button
                colorPalette="brand"
                onClick={() => void submit()}
                loading={busy}
                loadingText="Registering"
                disabled={!tenantId || !withdrawAddress || !slug}
              >
                Register
              </Button>
            </Dialog.Footer>
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  );
}
