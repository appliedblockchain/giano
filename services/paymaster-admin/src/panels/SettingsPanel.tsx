import type { GianoPaymasterClient, PaymasterOverview, PaymasterRoleName } from '@appliedblockchain/giano-paymaster-sdk';
import { Alert, Button, Field, HStack, Input, SimpleGrid, Stack, Text } from '@chakra-ui/react';
import { useState } from 'react';
import { LuPause, LuPlay, LuTrash2 } from 'react-icons/lu';
import { parseEther, type Address } from 'viem';
import { Copyable, SectionCard } from '../components/ui';
import { useWrite } from '../hooks/useWrite';
import { eth, exactEth } from '../lib/format';

type Props = {
  client: GianoPaymasterClient;
  overview: PaymasterOverview;
  myRoles: readonly PaymasterRoleName[];
  refresh: () => Promise<void>;
};

/**
 * Signing keys, pricing, operational parameters, stake and treasury.
 *
 * Each block states the role it needs and is disabled without it, rather than being hidden. An
 * operator who cannot do something should still be able to see that the control exists and which
 * role would let them — hiding it just produces a support ticket.
 */
export function SettingsPanel({ client, overview, myRoles, refresh }: Props) {
  const { run, busy } = useWrite(refresh);
  const has = (role: PaymasterRoleName) => myRoles.includes(role);

  const [signer, setSigner] = useState('');
  const [defaultFee, setDefaultFee] = useState('');
  const [postOpGas, setPostOpGas] = useState('');
  const [penalty, setPenalty] = useState('');
  const [stakeAmount, setStakeAmount] = useState('1');
  const [stakeDelay, setStakeDelay] = useState('86400');
  const [feeTo, setFeeTo] = useState('');
  const [feeAmount, setFeeAmount] = useState('');

  return (
    <Stack gap="4">
      <SectionCard
        title="Sponsorship signing keys"
        subtitle="Only these keys can authorise a sponsorship. Revocation takes effect immediately — set membership is checked before the signature."
      >
        {overview.signers.length === 0 ? (
          <Alert.Root status="error" mb="3">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>No signing keys authorised</Alert.Title>
              <Alert.Description>Nothing can be sponsored until one is added.</Alert.Description>
            </Alert.Content>
          </Alert.Root>
        ) : (
          <Stack gap="2" mb="3">
            {overview.signers.map((key) => (
              <HStack key={key} justify="space-between">
                <Copyable value={key} label="Signing key" />
                <Button
                  size="xs"
                  variant="ghost"
                  colorPalette="red"
                  disabled={!has('SIGNER_ADMIN_ROLE') || busy}
                  onClick={() => void run('Revoke signing key', () => client.removeSigner(key))}
                >
                  <LuTrash2 /> Revoke
                </Button>
              </HStack>
            ))}
          </Stack>
        )}
        <HStack gap="2" align="flex-end">
          <Field.Root>
            <Field.Label fontSize="sm">Add a signing key</Field.Label>
            <Input size="sm" value={signer} onChange={(event) => setSigner(event.target.value)} placeholder="0x…" />
          </Field.Root>
          <Button
            size="sm"
            colorPalette="brand"
            disabled={!has('SIGNER_ADMIN_ROLE') || busy || !signer}
            onClick={() => void run('Authorise signing key', () => client.addSigner(signer as Address))}
          >
            Add
          </Button>
        </HStack>
        <RoleHint role="SIGNER_ADMIN_ROLE" has={has('SIGNER_ADMIN_ROLE')} />
      </SectionCard>

      <SimpleGrid columns={{ base: 1, lg: 2 }} gap="4">
        <SectionCard title="Pricing" subtitle="The platform fee charged per sponsored operation, before any per-tenant override">
          <Stack gap="3">
            <Text fontSize="sm" color="fg.muted">
              Currently {exactEth(overview.config.defaultFeeWei)}.
            </Text>
            <HStack gap="2" align="flex-end">
              <Field.Root>
                <Field.Label fontSize="sm">New default fee (ETH)</Field.Label>
                <Input size="sm" value={defaultFee} onChange={(event) => setDefaultFee(event.target.value)} placeholder="0.0001" inputMode="decimal" />
              </Field.Root>
              <Button
                size="sm"
                colorPalette="brand"
                disabled={!has('FEE_ADMIN_ROLE') || busy || !defaultFee}
                onClick={() => void run('Set default fee', () => client.setDefaultFee(parseEther(defaultFee)))}
              >
                Set
              </Button>
            </HStack>
            <RoleHint role="FEE_ADMIN_ROLE" has={has('FEE_ADMIN_ROLE')} />
          </Stack>
        </SectionCard>

        <SectionCard title="Operational parameters" subtitle="Bounds on the costs settlement cannot observe. Charged as an upper bound on purpose.">
          <Stack gap="3">
            <HStack gap="2" align="flex-end">
              <Field.Root>
                <Field.Label fontSize="sm">Post-op gas allowance</Field.Label>
                <Input
                  size="sm"
                  value={postOpGas}
                  onChange={(event) => setPostOpGas(event.target.value)}
                  placeholder={String(overview.config.postOpGasAllowance)}
                  inputMode="numeric"
                />
              </Field.Root>
              <Button
                size="sm"
                variant="outline"
                disabled={!has('PARAM_ADMIN_ROLE') || busy || !postOpGas}
                onClick={() => void run('Set post-op gas allowance', () => client.setPostOpGasAllowance(Number(postOpGas)))}
              >
                Set
              </Button>
            </HStack>
            <HStack gap="2" align="flex-end">
              <Field.Root>
                <Field.Label fontSize="sm">Penalty (bps, max 5000)</Field.Label>
                <Input
                  size="sm"
                  value={penalty}
                  onChange={(event) => setPenalty(event.target.value)}
                  placeholder={String(overview.config.penaltyBps)}
                  inputMode="numeric"
                />
              </Field.Root>
              <Button
                size="sm"
                variant="outline"
                disabled={!has('PARAM_ADMIN_ROLE') || busy || !penalty}
                onClick={() => void run('Set penalty bps', () => client.setPenaltyBps(Number(penalty)))}
              >
                Set
              </Button>
            </HStack>
            <RoleHint role="PARAM_ADMIN_ROLE" has={has('PARAM_ADMIN_ROLE')} />
          </Stack>
        </SectionCard>

        <SectionCard title="Stake" subtitle="Bundlers reject an unstaked validating paymaster, which surfaces to a client as an unexplained failure">
          <Stack gap="3">
            <Text fontSize="sm" color="fg.muted">
              {overview.stake.staked
                ? `Staked ${exactEth(overview.stake.stakeWei)}, unstake delay ${overview.stake.unstakeDelaySec}s.`
                : 'Not staked.'}
              {overview.stake.withdrawTime > 0 && ' Unlocking — bundlers will stop accepting operations.'}
            </Text>
            <HStack gap="2" align="flex-end">
              <Field.Root>
                <Field.Label fontSize="sm">Amount (ETH)</Field.Label>
                <Input size="sm" value={stakeAmount} onChange={(event) => setStakeAmount(event.target.value)} inputMode="decimal" />
              </Field.Root>
              <Field.Root>
                <Field.Label fontSize="sm">Unstake delay (s)</Field.Label>
                <Input size="sm" value={stakeDelay} onChange={(event) => setStakeDelay(event.target.value)} inputMode="numeric" />
              </Field.Root>
              <Button
                size="sm"
                colorPalette="brand"
                disabled={!has('STAKE_ADMIN_ROLE') || busy}
                onClick={() => void run('Add stake', () => client.addStake(parseEther(stakeAmount), Number(stakeDelay)))}
              >
                Stake
              </Button>
            </HStack>
            <RoleHint role="STAKE_ADMIN_ROLE" has={has('STAKE_ADMIN_ROLE')} />
          </Stack>
        </SectionCard>

        <SectionCard
          title="Treasury"
          subtitle="Withdrawal is capped at what has accrued — that cap is what keeps tenant balances out of reach of this path"
        >
          <Stack gap="3">
            <Text fontSize="sm" color="fg.muted">
              {eth(overview.solvency.treasuryWei)} ETH accrued ({exactEth(overview.solvency.treasuryWei)}).
            </Text>
            <HStack gap="2" align="flex-end">
              <Field.Root>
                <Field.Label fontSize="sm">To</Field.Label>
                <Input size="sm" value={feeTo} onChange={(event) => setFeeTo(event.target.value)} placeholder="0x…" />
              </Field.Root>
              <Field.Root>
                <Field.Label fontSize="sm">Amount (ETH)</Field.Label>
                <Input size="sm" value={feeAmount} onChange={(event) => setFeeAmount(event.target.value)} inputMode="decimal" />
              </Field.Root>
              <Button
                size="sm"
                colorPalette="accent"
                disabled={!has('FEE_COLLECTOR_ROLE') || busy || !feeTo || !feeAmount}
                onClick={() => void run('Withdraw fees', () => client.withdrawFees(feeTo as Address, parseEther(feeAmount)))}
              >
                Withdraw
              </Button>
            </HStack>
            <RoleHint role="FEE_COLLECTOR_ROLE" has={has('FEE_COLLECTOR_ROLE')} />
          </Stack>
        </SectionCard>
      </SimpleGrid>

      <SectionCard title="Pause" subtitle="Halts acceptance of new sponsorships and nothing else. Tenant withdrawals keep working.">
        <HStack gap="3">
          <Button
            colorPalette={overview.config.paused ? 'green' : 'orange'}
            disabled={!has('PAUSER_ROLE') || busy}
            onClick={() =>
              void run(overview.config.paused ? 'Unpause' : 'Pause', () => (overview.config.paused ? client.unpause() : client.pause()))
            }
          >
            {overview.config.paused ? <LuPlay /> : <LuPause />}
            {overview.config.paused ? 'Resume sponsorships' : 'Pause sponsorships'}
          </Button>
          <Text fontSize="sm" color="fg.muted">
            Currently {overview.config.paused ? 'paused' : 'accepting new sponsorships'}.
          </Text>
        </HStack>
        <RoleHint role="PAUSER_ROLE" has={has('PAUSER_ROLE')} />
      </SectionCard>
    </Stack>
  );
}

function RoleHint({ role, has }: { role: PaymasterRoleName; has: boolean }) {
  if (has) return null;
  return (
    <Text fontSize="xs" color="fg.muted" mt="2">
      Requires {role}, which the connected account does not hold.
    </Text>
  );
}
