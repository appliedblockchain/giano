import type { HealthReport } from '@appliedblockchain/giano-paymaster-sdk';
import { Badge, Box, HStack, Stack, Text } from '@chakra-ui/react';
import { LuCircleAlert, LuCircleCheck, LuTriangleAlert } from 'react-icons/lu';
import { SectionCard } from '../components/ui';

/**
 * The same checks `giano-doctor` runs, evaluated in the browser from the overview already on
 * screen. Same thresholds, same verdicts — a console that disagreed with the deployment gate
 * about whether a paymaster is usable would be worse than no console.
 */
const LEVEL = {
  ok: { icon: LuCircleCheck, color: 'green.fg', palette: 'green', label: 'ok' },
  warn: { icon: LuTriangleAlert, color: 'orange.fg', palette: 'orange', label: 'check' },
  fail: { icon: LuCircleAlert, color: 'red.fg', palette: 'red', label: 'failing' },
} as const;

export function HealthPanel({ health }: { health: HealthReport }) {
  const overall = LEVEL[health.level];

  return (
    <SectionCard
      title="Deployment health"
      subtitle="The checks the CI gate runs, evaluated against the state above"
      action={
        <Badge colorPalette={overall.palette} variant="solid" size="lg">
          {overall.label}
        </Badge>
      }
    >
      <Stack gap="3">
        {health.checks.map((check) => {
          const level = LEVEL[check.level];
          const Icon = level.icon;
          return (
            <Box key={check.id} borderLeftWidth="3px" borderColor={level.color} pl="3" py="0.5">
              <HStack gap="2" align="center">
                <Box color={level.color} display="flex">
                  <Icon aria-hidden />
                </Box>
                <Text fontWeight="medium">{check.label}</Text>
              </HStack>
              <Text fontSize="sm" color="fg.muted" fontFamily="mono" mt="0.5">
                {check.detail}
              </Text>
              {check.remedy && (
                <Text fontSize="sm" mt="1">
                  → {check.remedy}
                </Text>
              )}
            </Box>
          );
        })}
      </Stack>
    </SectionCard>
  );
}
