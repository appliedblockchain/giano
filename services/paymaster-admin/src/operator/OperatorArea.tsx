import type { GianoPaymasterClient, PaymasterOverview, PaymasterRoleName } from '@appliedblockchain/giano-paymaster-sdk';
import { Badge, Button, HStack, Stack, Tabs, Text } from '@chakra-ui/react';
import { LuLogOut, LuShieldCheck, LuUsers } from 'react-icons/lu';
import { Copyable } from '../components/ui';
import type { Deployment } from '../config';
import type { ConnectedWallet } from '../lib/chain';
import { useOperator } from '../lib/operator-session';
import { OperatorsTab } from './OperatorsTab';
import { SignIn } from './SignIn';
import { TenantsTab } from './TenantsTab';

export type OperatorAreaProps = {
  deployment: Deployment;
  wallet: ConnectedWallet | undefined;
  connect: () => Promise<ConnectedWallet | undefined>;
  connecting: boolean;
  /** The chain side: the paymaster roster the registry is joined to, and the roles that gate on-chain steps. */
  client: GianoPaymasterClient | undefined;
  overview: PaymasterOverview | undefined;
  myRoles: readonly PaymasterRoleName[];
  refreshChain: () => Promise<void>;
};

/**
 * The Operator area (specs/OPERATOR-ADMIN-SPECS.md §11.2): Giano's own staff administering the
 * tenant registry in wallet-api, and the list of operators itself. Shown only where the console has an operator API to reach.
 * Without a session it is the sign-in view and nothing else.
 */
export function OperatorArea(props: OperatorAreaProps) {
  const { session, signOut } = useOperator();
  if (!session) return <SignIn {...props} />;

  return (
    <Stack gap="4">
      <HStack justify="space-between" flexWrap="wrap" gap="3" borderWidth="1px" rounded="lg" px="4" py="2" bg="surface">
        <HStack gap="3" flexWrap="wrap">
          <Badge colorPalette="brand" variant="solid">
            operator
          </Badge>
          <Text fontWeight="medium">{session.operator.id}</Text>
          <Copyable value={session.operator.address} label="Operator address" />
          <Text fontSize="xs" color="fg.muted">
            session until {session.expiresAt.toLocaleTimeString()}
          </Text>
        </HStack>
        <Button size="sm" variant="ghost" onClick={() => void signOut()}>
          <LuLogOut /> Sign out
        </Button>
      </HStack>

      <Tabs.Root defaultValue="tenants" lazyMount>
        <Tabs.List mb="4">
          <Tabs.Trigger value="tenants">
            <LuUsers /> Tenants
          </Tabs.Trigger>
          <Tabs.Trigger value="operators">
            <LuShieldCheck /> Operators
          </Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="tenants">
          <TenantsTab {...props} />
        </Tabs.Content>
        <Tabs.Content value="operators">
          <OperatorsTab />
        </Tabs.Content>
      </Tabs.Root>
    </Stack>
  );
}
