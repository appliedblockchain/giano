import { ROLE_DESCRIPTIONS, type GianoPaymasterClient, type PaymasterRoleName, type RoleHolders } from '@appliedblockchain/giano-paymaster-sdk';
import { Alert, Badge, Box, Button, HStack, Input, NativeSelect, Stack, Table, Text } from '@chakra-ui/react';
import { useState } from 'react';
import type { Address } from 'viem';
import { Copyable, SectionCard } from '../components/ui';
import { useWrite } from '../hooks/useWrite';

type Props = {
  client: GianoPaymasterClient;
  roles: readonly RoleHolders[];
  myRoles: readonly PaymasterRoleName[];
  account: Address | undefined;
  refresh: () => Promise<void>;
};

/**
 * Role holders, and what each role is actually for.
 *
 * The "may not" column is the point rather than decoration: the security argument is a set of
 * pairs — the fee admin cannot collect the fees it sets, the fee collector cannot change the rate,
 * no role at all can reach a tenant balance — and an operator reviewing holders needs to see the
 * pair to know whether a grant is safe.
 */
export function RolesPanel({ client, roles, myRoles, account, refresh }: Props) {
  const { run, busy } = useWrite(refresh);
  const canGrant = myRoles.includes('ROLE_ADMIN');

  const [role, setRole] = useState<PaymasterRoleName>('TENANT_ADMIN_ROLE');
  const [target, setTarget] = useState('');

  const defaultAdmin = roles.find((entry) => entry.name === 'DEFAULT_ADMIN_ROLE');

  return (
    <Stack gap="4">
      {defaultAdmin && defaultAdmin.holders.length > 0 && (
        <Alert.Root status="error">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>DEFAULT_ADMIN_ROLE is held</Alert.Title>
            <Alert.Description>
              {defaultAdmin.holders.join(', ')} — this is a superuser by another name. The design grants every power through its own named role
              instead; revoke it.
            </Alert.Description>
          </Alert.Content>
        </Alert.Root>
      )}

      <SectionCard
        title="Roles"
        subtitle="There is no owner and no superuser. Every role is administered by ROLE_ADMIN, which in production is a timelock."
      >
        <Table.ScrollArea borderWidth="1px" rounded="md">
          <Table.Root size="sm">
            <Table.Header>
              <Table.Row>
                <Table.ColumnHeader>Role</Table.ColumnHeader>
                <Table.ColumnHeader>Holders</Table.ColumnHeader>
                <Table.ColumnHeader>What it can and cannot do</Table.ColumnHeader>
                {canGrant && <Table.ColumnHeader />}
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {roles
                .filter((entry) => entry.name !== 'DEFAULT_ADMIN_ROLE')
                .map((entry) => {
                  const description = ROLE_DESCRIPTIONS[entry.name as PaymasterRoleName];
                  return (
                    <Table.Row key={entry.role}>
                      <Table.Cell>
                        <Stack gap="1">
                          <Text fontWeight="medium" fontSize="sm">
                            {entry.name}
                          </Text>
                          {myRoles.includes(entry.name as PaymasterRoleName) && (
                            <Badge colorPalette="brand" variant="subtle" size="sm" width="fit-content">
                              you hold this
                            </Badge>
                          )}
                        </Stack>
                      </Table.Cell>
                      <Table.Cell>
                        {entry.holders.length === 0 ? (
                          <Text fontSize="sm" color="fg.muted">
                            nobody
                          </Text>
                        ) : (
                          <Stack gap="1">
                            {entry.holders.map((holder) => (
                              <HStack key={holder} gap="2">
                                <Copyable value={holder} label={entry.name} />
                                {canGrant && (
                                  <Button
                                    size="xs"
                                    variant="ghost"
                                    colorPalette="red"
                                    disabled={busy}
                                    onClick={() => void run(`Revoke ${entry.name}`, () => client.revokeRole(entry.name as PaymasterRoleName, holder))}
                                  >
                                    revoke
                                  </Button>
                                )}
                              </HStack>
                            ))}
                          </Stack>
                        )}
                      </Table.Cell>
                      <Table.Cell fontSize="sm" color="fg.muted">
                        <Text>May {description?.may}.</Text>
                        <Text mt="0.5">
                          May <Text as="span" fontWeight="medium">not</Text> {description?.mayNot}.
                        </Text>
                      </Table.Cell>
                      {canGrant && <Table.Cell />}
                    </Table.Row>
                  );
                })}
            </Table.Body>
          </Table.Root>
        </Table.ScrollArea>

        {!defaultAdmin?.holders.length && (
          <Text fontSize="xs" color="accent.fg" mt="3">
            ✓ DEFAULT_ADMIN_ROLE is held by nobody — there is no superuser.
          </Text>
        )}
      </SectionCard>

      {canGrant && (
        <SectionCard title="Grant a role" subtitle="You hold ROLE_ADMIN. On a production deployment this action would go through the timelock.">
          <HStack gap="3" flexWrap="wrap" align="flex-end">
            <Box minW="14rem">
              <Text fontSize="sm" mb="1">
                Role
              </Text>
              <NativeSelect.Root size="sm">
                <NativeSelect.Field value={role} onChange={(event) => setRole(event.currentTarget.value as PaymasterRoleName)}>
                  {roles
                    .filter((entry) => entry.name !== 'DEFAULT_ADMIN_ROLE')
                    .map((entry) => (
                      <option key={entry.role} value={entry.name}>
                        {entry.name}
                      </option>
                    ))}
                </NativeSelect.Field>
                <NativeSelect.Indicator />
              </NativeSelect.Root>
            </Box>
            <Box flex="1" minW="20rem">
              <Text fontSize="sm" mb="1">
                Address
              </Text>
              <Input size="sm" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="0x…" />
            </Box>
            <Button
              size="sm"
              colorPalette="brand"
              disabled={busy || !target}
              onClick={() => void run(`Grant ${role}`, () => client.grantRole(role, target as Address))}
            >
              Grant
            </Button>
          </HStack>
          {account && (
            <Text fontSize="xs" color="fg.muted" mt="3">
              Signing as {account}.
            </Text>
          )}
        </SectionCard>
      )}
    </Stack>
  );
}
