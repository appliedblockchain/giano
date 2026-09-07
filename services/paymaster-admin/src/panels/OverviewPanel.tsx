import type { PaymasterOverview } from '@appliedblockchain/giano-paymaster-sdk';
import { Alert, Box, HStack, SimpleGrid, Text } from '@chakra-ui/react';
import { LuTriangleAlert } from 'react-icons/lu';
import { Copyable, SectionCard, Stat } from '../components/ui';
import { eth, exactEth } from '../lib/format';

/**
 * The solvency position, first and largest.
 *
 * `Σ tenant balances + treasury ≤ deposit` is the property the whole paymaster rests on, and a
 * breach is an insolvency rather than a warning — so it gets the loudest treatment on the page
 * and says what to do, not just that something is wrong.
 */
export function OverviewPanel({ overview }: { overview: PaymasterOverview }) {
  const { solvency, config, stake, tenants } = overview;
  const inDeficit = tenants.filter((tenant) => tenant.deficit > 0n);

  return (
    <>
      {!solvency.holds && (
        <Alert.Root status="error" mb="4">
          <Alert.Indicator>
            <LuTriangleAlert />
          </Alert.Indicator>
          <Alert.Content>
            <Alert.Title>Accounting invariant breached</Alert.Title>
            <Alert.Description>
              Claims of {exactEth(solvency.claimsWei)} exceed the {exactEth(solvency.depositWei)} deposit. This is an insolvency: stop issuing
              sponsorships and investigate before anything else.
            </Alert.Description>
          </Alert.Content>
        </Alert.Root>
      )}

      {config.paused && (
        <Alert.Root status="warning" mb="4">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>Paused</Alert.Title>
            <Alert.Description>No new sponsorships are being accepted. Tenant withdrawals still work — a pause must not trap funds.</Alert.Description>
          </Alert.Content>
        </Alert.Root>
      )}

      {inDeficit.length > 0 && (
        <Alert.Root status="warning" mb="4">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>
              {inDeficit.length} tenant{inDeficit.length === 1 ? '' : 's'} in deficit
            </Alert.Title>
            <Alert.Description>
              {inDeficit.map((tenant) => tenant.slug ?? tenant.uuid).join(', ')} cannot transact until funded. Funding clears the deficit first, then
              credits the remainder.
            </Alert.Description>
          </Alert.Content>
        </Alert.Root>
      )}

      <SimpleGrid columns={{ base: 1, md: 2, xl: 4 }} gap="4" mb="4">
        <SectionCard title="Deposit" subtitle="What actually pays for sponsored gas">
          <Stat label="at the EntryPoint" value={`${eth(solvency.depositWei)} ETH`} hint={exactEth(solvency.depositWei)} />
        </SectionCard>
        <SectionCard title="Tenant balances" subtitle={`${tenants.length} registered`}>
          <Stat label="sum of all tenants" value={`${eth(solvency.tenantBalancesWei)} ETH`} hint={exactEth(solvency.tenantBalancesWei)} />
        </SectionCard>
        <SectionCard title="Treasury" subtitle="Accrued platform fees">
          <Stat label="collectable" value={`${eth(solvency.treasuryWei)} ETH`} hint={exactEth(solvency.treasuryWei)} />
        </SectionCard>
        <SectionCard title="Stake" subtitle="Bundlers reject an unstaked paymaster">
          <Stat
            label={stake.staked ? `unstake delay ${stake.unstakeDelaySec}s` : 'not staked'}
            value={`${eth(stake.stakeWei)} ETH`}
            hint={exactEth(stake.stakeWei)}
            tone={stake.staked ? 'default' : 'bad'}
          />
        </SectionCard>
      </SimpleGrid>

      <SimpleGrid columns={{ base: 1, lg: 2 }} gap="4">
        <SectionCard
          title="Solvency"
          subtitle="Σ tenant balances + treasury ≤ deposit. At most, never equal — the difference is expected slack."
        >
          <SimpleGrid columns={2} gap="4">
            <Stat label="claims" value={`${eth(solvency.claimsWei)} ETH`} hint={exactEth(solvency.claimsWei)} />
            <Stat label="deposit" value={`${eth(solvency.depositWei)} ETH`} hint={exactEth(solvency.depositWei)} />
            <Stat
              label="unattributed slack"
              value={`${eth(solvency.slackWei)} ETH`}
              hint={exactEth(solvency.slackWei)}
              tone={solvency.holds ? 'good' : 'bad'}
            />
            <Stat label="invariant" value={solvency.holds ? 'holds' : 'BREACHED'} tone={solvency.holds ? 'good' : 'bad'} />
          </SimpleGrid>
          <Text fontSize="xs" color="fg.muted" mt="4">
            The EntryPoint also debits the deposit for costs settlement cannot observe, so the ledger is charged a deliberately generous upper bound
            and the difference accumulates here. Slack growing slowly is expected; slack shrinking towards zero is not.
          </Text>
        </SectionCard>

        <SectionCard title="Configuration" subtitle="What every sponsorship is priced against">
          <SimpleGrid columns={2} gap="4">
            <Stat label="default fee" value={`${eth(config.defaultFeeWei, 6)} ETH`} hint={exactEth(config.defaultFeeWei)} />
            <Stat label="post-op allowance" value={`${config.postOpGasAllowance.toLocaleString()}`} hint="gas units charged for settlement" />
            <Stat label="penalty" value={`${config.penaltyBps} bps`} hint="bound on the EntryPoint's unused-gas penalty" />
            <Stat label="accepting work" value={config.paused ? 'paused' : 'yes'} tone={config.paused ? 'bad' : 'good'} />
          </SimpleGrid>
          <HStack gap="2" mt="4" flexWrap="wrap">
            <Text fontSize="xs" color="fg.muted">
              EntryPoint
            </Text>
            <Copyable value={config.entryPoint} label="EntryPoint" />
            <Text fontSize="xs" color="fg.muted">
              paymaster
            </Text>
            <Copyable value={overview.address} label="Paymaster" />
            <Text fontSize="xs" color="fg.muted">
              chain {overview.chainId}
            </Text>
          </HStack>
          <Box mt="3">
            <Text fontSize="xs" color="fg.muted">
              The paymaster address is the proxy and is stable across upgrades — it is what tenants fund, so it must never change.
            </Text>
          </Box>
        </SectionCard>
      </SimpleGrid>
    </>
  );
}
