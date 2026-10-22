import { Alert, Box, Button, Checkbox, HStack, Spinner, Stack, Table, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { LuPlus, LuRefreshCw } from 'react-icons/lu';
import { Copyable, SectionCard } from '../components/ui';
import type { TenantSummary } from '../lib/operator-api';
import { useOperator } from '../lib/operator-session';
import { CreateTenantDialog } from './CreateTenantDialog';
import type { OperatorAreaProps } from './OperatorArea';
import { LifecycleBadge, OnChainBadge, onChainState, OwnerBadge, rosterByUuid } from './shared';
import { TenantDrawer } from './TenantDrawer';

/**
 * The tenant registry, joined to the paymaster roster (specs/OPERATOR-ADMIN-SPECS.md §11.2).
 *
 * Two sources that know about the same tenants and neither of which can see the other: wallet-api
 * holds who a tenant is, the paymaster holds whether it can be sponsored. Matched on the tenant id
 * the two share, the table shows a tenant that exists in one and not the other — including, in its
 * own group, roster entries no registry row accounts for, which nothing else in Giano surfaces.
 *
 * Deleted tenants are always fetched, because a tombstone still explains a roster entry, and shown
 * only when asked for.
 */
export function TenantsTab(props: OperatorAreaProps) {
  const { deployment, overview, myRoles } = props;
  const { run } = useOperator();
  const [live, setLive] = useState<TenantSummary[]>();
  const [deleted, setDeleted] = useState<TenantSummary[]>([]);
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string>();
  const [selected, setSelected] = useState<string>();
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [current, tombstones] = await Promise.all([run((api) => api.list()), run((api) => api.list('deleted'))]);
      if (!current || !tombstones) return; // the session ended; the area is back on sign-in
      if (!current.ok) return setLoadError(current.error.message);
      setLoadError(undefined);
      setLive(current.value.tenants);
      if (tombstones.ok) setDeleted(tombstones.value.tenants);
    } catch (cause) {
      setLoadError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, [run]);

  useEffect(() => {
    void load();
  }, [load]);

  const roster = useMemo(() => rosterByUuid(overview), [overview]);
  const rows = useMemo(() => [...(live ?? []), ...(includeDeleted ? deleted : [])], [live, deleted, includeDeleted]);
  const rosterOnly = useMemo(() => {
    if (!overview || !live) return [];
    const known = new Set([...live, ...deleted].map((tenant) => tenant.id.toLowerCase()));
    return overview.tenants.filter((tenant) => !known.has(tenant.uuid.toLowerCase()));
  }, [overview, live, deleted]);

  const refreshAll = async () => {
    await Promise.all([load(), props.refreshChain()]);
  };

  return (
    <Stack gap="4">
      <SectionCard
        title={`Tenant registry${live ? ` (${live.length})` : ''}`}
        subtitle={`Tenants in wallet-api, with their state on the ${deployment.name} paymaster (chain ${deployment.chainId}). Changes here take effect on the next request — nothing is redeployed.`}
        action={
          <HStack>
            <Button size="sm" variant="ghost" onClick={() => void refreshAll()} loading={loading} aria-label="Refresh tenants">
              <LuRefreshCw />
            </Button>
            <Button size="sm" colorPalette="brand" onClick={() => setCreating(true)}>
              <LuPlus /> Create tenant
            </Button>
          </HStack>
        }
      >
        <Stack gap="3">
          <HStack justify="space-between">
            <Checkbox.Root size="sm" checked={includeDeleted} onCheckedChange={(event) => setIncludeDeleted(event.checked === true)}>
              <Checkbox.HiddenInput />
              <Checkbox.Control />
              <Checkbox.Label>Show deleted tenants ({deleted.length})</Checkbox.Label>
            </Checkbox.Root>
            {!overview && (
              <Text fontSize="xs" color="fg.muted">
                The paymaster has not been read yet, so the on-chain column is unknown.
              </Text>
            )}
          </HStack>

          {loadError && (
            <Alert.Root status="error" size="sm">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>Could not read the tenant registry</Alert.Title>
                <Alert.Description>{loadError}</Alert.Description>
              </Alert.Content>
            </Alert.Root>
          )}

          {!live && loading ? (
            <HStack py="8" justify="center">
              <Spinner />
            </HStack>
          ) : (
            <Table.ScrollArea borderWidth="1px" rounded="md">
              <Table.Root size="sm" interactive stickyHeader>
                <Table.Header>
                  <Table.Row>
                    <Table.ColumnHeader>Tenant</Table.ColumnHeader>
                    <Table.ColumnHeader>Id</Table.ColumnHeader>
                    <Table.ColumnHeader>Status</Table.ColumnHeader>
                    <Table.ColumnHeader>Managed by</Table.ColumnHeader>
                    <Table.ColumnHeader>Wallet origin</Table.ColumnHeader>
                    <Table.ColumnHeader textAlign="end">Users</Table.ColumnHeader>
                    <Table.ColumnHeader>On chain {deployment.chainId}</Table.ColumnHeader>
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {rows.map((tenant) => (
                    <Table.Row key={tenant.id} cursor="pointer" onClick={() => setSelected(tenant.slug)} data-testid={`tenant-row-${tenant.slug}`}>
                      <Table.Cell>
                        <Text fontWeight="medium">{tenant.slug}</Text>
                        <Text fontSize="xs" color="fg.muted">
                          {tenant.rpName}
                        </Text>
                      </Table.Cell>
                      <Table.Cell onClick={(event) => event.stopPropagation()}>
                        <Copyable value={tenant.id} label="Tenant id" />
                      </Table.Cell>
                      <Table.Cell>
                        <LifecycleBadge status={tenant.status} />
                      </Table.Cell>
                      <Table.Cell>
                        <OwnerBadge managedBy={tenant.managedBy} />
                      </Table.Cell>
                      <Table.Cell fontFamily="mono" fontSize="xs">
                        {tenant.walletOrigin}
                      </Table.Cell>
                      <Table.Cell textAlign="end">{tenant.users}</Table.Cell>
                      <Table.Cell>
                        <OnChainBadge state={onChainState(roster, tenant.id)} />
                      </Table.Cell>
                    </Table.Row>
                  ))}
                  {rows.length === 0 && (
                    <Table.Row>
                      <Table.Cell colSpan={7}>
                        <Text color="fg.muted">No tenants yet.</Text>
                      </Table.Cell>
                    </Table.Row>
                  )}
                </Table.Body>
              </Table.Root>
            </Table.ScrollArea>
          )}
        </Stack>
      </SectionCard>

      {rosterOnly.length > 0 && (
        <SectionCard
          title={`On-chain only (${rosterOnly.length})`}
          subtitle="Registered on this paymaster but with no tenant in wallet-api — another deployment's tenant on a shared paymaster, or a registration whose backend tenant was never created."
        >
          <Stack gap="2">
            {rosterOnly.map((tenant) => (
              <HStack key={tenant.uuid} gap="3" data-testid="roster-only">
                <Copyable value={tenant.uuid} label="Tenant id" />
                <OnChainBadge state={tenant.enabled ? 'enabled' : 'disabled'} />
              </HStack>
            ))}
          </Stack>
        </SectionCard>
      )}

      {selected && (
        <TenantDrawer
          {...props}
          slug={selected}
          onClose={() => setSelected(undefined)}
          onChanged={() => void load()}
          canAdminister={myRoles.includes('TENANT_ADMIN_ROLE')}
          onChain={(id) => onChainState(roster, id)}
        />
      )}
      <Box>
        <CreateTenantDialog {...props} open={creating} onClose={() => setCreating(false)} onCreated={() => void load()} />
      </Box>
    </Stack>
  );
}
