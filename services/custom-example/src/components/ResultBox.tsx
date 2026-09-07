import { Box, Text } from '@chakra-ui/react';

type Tone = 'neutral' | 'accent' | 'error';

type ResultBoxProps = {
  label: string;
  value: string;
  tone?: Tone;
};

const toneStyles: Record<Tone, { bg: string; border: string; label: string }> = {
  neutral: { bg: 'bg.subtle', border: 'border', label: 'fg.muted' },
  accent: { bg: 'accent.subtle', border: 'accent.muted', label: 'accent.fg' },
  error: { bg: 'red.50', border: 'red.300', label: 'red.600' },
};

/** Read-only monospace display for hashes, signatures, and status/error output. */
export function ResultBox({ label, value, tone = 'neutral' }: ResultBoxProps) {
  const s = toneStyles[tone];
  return (
    <Box borderWidth="1px" borderColor={s.border} rounded="md" bg={s.bg} p="3">
      <Text fontSize="xs" fontWeight="semibold" color={s.label} mb="1">
        {label}
      </Text>
      <Text fontFamily="mono" fontSize="sm" wordBreak="break-all" color="fg" whiteSpace="pre-wrap">
        {value}
      </Text>
    </Box>
  );
}
