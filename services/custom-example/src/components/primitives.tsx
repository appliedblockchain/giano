import { Box, Button, Card, Code, Collapsible, DataList, HStack, NativeSelect, Spinner, Stack, Status, Text, Wrap } from '@chakra-ui/react';
import { useMemo, useState, type ReactNode } from 'react';
import { LuChevronDown, LuChevronRight } from 'react-icons/lu';
import { formatDuration, formatEth, hexToBigInt, shortHex, toJson } from '../lib/format';
import type { EntryStatus, LedgerEntry } from '../lib/ledger';
import { ClipboardIconButton, ClipboardRoot } from './ui/clipboard';

/**
 * The shared UI vocabulary (design.md D8 UX rules): status is a dot plus text, never a stack of
 * badges; one action picker per card; every outcome is a row with a one-line summary and details folded
 * behind it; a jump bar under the header. Chakra components and theme tokens only — no CSS (R4).
 */

// ---- SectionCard ----------------------------------------------------------------------------------

/** A Giano SDK call or member and what this card uses it for. */
export type SdkItem = [name: string, note: string];

/** "Giano SDK used here": the calls a card makes, as chips, with a folded explanation of each. */
export function SdkUsage({ items, compact }: { items: SdkItem[]; compact?: boolean }) {
  if (!items.length) return null;
  return (
    <Stack gap="2">
      <Wrap gap="1.5" align="center">
        <Text fontSize="xs" fontWeight="medium" color="fg.muted" textTransform="uppercase" letterSpacing="wide">
          Giano SDK used here
        </Text>
        {items.map(([name]) => (
          <Code key={name} size="sm" variant="subtle" colorPalette="brand">
            {name}
          </Code>
        ))}
      </Wrap>
      {!compact && (
        <Disclosure label="What each call does">
          <DataList.Root orientation="horizontal" size="sm" gap="1.5">
            {items.map(([name, note]) => (
              <DataList.Item key={name} alignItems="baseline">
                <DataList.ItemLabel minW="64">
                  <Code size="sm" variant="plain">
                    {name}
                  </Code>
                </DataList.ItemLabel>
                <DataList.ItemValue fontSize="sm">{note}</DataList.ItemValue>
              </DataList.Item>
            ))}
          </DataList.Root>
        </Disclosure>
      )}
    </Stack>
  );
}

export function SectionCard({ id, title, description, children, aside, sdk }: { id: string; title: string; description?: string; children: ReactNode; aside?: ReactNode; sdk?: SdkItem[] }) {
  return (
    <Card.Root id={id} variant="outline" scrollMarginTop="28">
      <Card.Header>
        <HStack justify="space-between" align="flex-start" gap="4" flexWrap="wrap">
          <Stack gap="1">
            <Card.Title>{title}</Card.Title>
            {description && <Card.Description>{description}</Card.Description>}
          </Stack>
          {aside}
        </HStack>
        {sdk && <SdkUsage items={sdk} />}
      </Card.Header>
      <Card.Body>
        <Stack gap="5">{children}</Stack>
      </Card.Body>
    </Card.Root>
  );
}

// ---- StatusText ------------------------------------------------------------------------------------

export type Tone = 'green' | 'red' | 'orange' | 'gray' | 'brand' | 'accent';

export function StatusText({ tone, children, busy }: { tone: Tone; children: ReactNode; busy?: boolean }) {
  return (
    <Status.Root colorPalette={tone} fontWeight="medium" fontSize="sm">
      {busy ? <Spinner size="xs" /> : <Status.Indicator />}
      {children}
    </Status.Root>
  );
}

export const STATUS_TONE: Record<EntryStatus, Tone> = {
  pending: 'gray',
  submitted: 'gray',
  ok: 'green',
  confirmed: 'green',
  failed: 'red',
  violation: 'red',
  refused: 'orange',
  'timed-out': 'orange',
};

export const STATUS_LABEL: Record<EntryStatus, string> = {
  pending: 'pending',
  submitted: 'submitted',
  ok: 'ok',
  confirmed: 'confirmed',
  failed: 'failed',
  violation: 'violation',
  refused: 'refused',
  'timed-out': 'timed out',
};

export function EntryStatusText({ entry }: { entry: LedgerEntry }) {
  const busy = entry.status === 'pending' || entry.status === 'submitted';
  const label = entry.status === 'refused' && entry.expected ? 'refused · expected' : STATUS_LABEL[entry.status];
  return (
    <StatusText tone={STATUS_TONE[entry.status]} busy={busy}>
      {label}
    </StatusText>
  );
}

// ---- Mono / Hex ------------------------------------------------------------------------------------

export function Mono({ children, muted, size = 'xs' }: { children: ReactNode; muted?: boolean; size?: 'xs' | 'sm' }) {
  return (
    <Text as="span" fontFamily="mono" fontSize={size} color={muted ? 'fg.muted' : 'fg'} wordBreak="break-all">
      {children}
    </Text>
  );
}

export function HexWithCopy({ value, short }: { value: string; short?: boolean }) {
  return (
    <HStack gap="1" display="inline-flex">
      <Mono>{short ? shortHex(value) : value}</Mono>
      <ClipboardRoot value={value}>
        <ClipboardIconButton aria-label="Copy" variant="ghost" size="2xs" />
      </ClipboardRoot>
    </HStack>
  );
}

// ---- KeyValues -------------------------------------------------------------------------------------

export function KeyValues({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <DataList.Root orientation="horizontal" size="sm" gap="2">
      {items
        .filter(([, value]) => value !== undefined && value !== null && value !== '')
        .map(([label, value]) => (
          <DataList.Item key={label} alignItems="baseline">
            <DataList.ItemLabel minW="36" color="fg.muted">
              {label}
            </DataList.ItemLabel>
            <DataList.ItemValue minW="0" wordBreak="break-all">
              {typeof value === 'string' ? <Mono>{value}</Mono> : value}
            </DataList.ItemValue>
          </DataList.Item>
        ))}
    </DataList.Root>
  );
}

export function CodeBlock({ value }: { value: unknown }) {
  const text = typeof value === 'string' ? value : toJson(value);
  return (
    <Box as="pre" fontFamily="mono" fontSize="xs" whiteSpace="pre-wrap" wordBreak="break-all" bg="bg.subtle" borderWidth="1px" rounded="l2" p="3" m="0">
      {text}
    </Box>
  );
}

// ---- OutcomeRow ------------------------------------------------------------------------------------

function summaryOf(entry: LedgerEntry): string {
  const parts: string[] = [entry.chainName];
  if (entry.attribution) parts.push(entry.attribution.actualPayer === 'sponsored' ? 'gas paid by the app' : entry.attribution.actualPayer === 'self-paid' ? 'gas paid by the account' : 'payer unknown');
  else if (entry.declaredPayer) parts.push(entry.declaredPayer === 'sponsored' ? 'expected: gas paid by the app' : 'expected: gas paid by the account');
  if (entry.attribution?.matchesDeclared === false) parts.push('payer differs from what was declared');
  if (entry.userOpHash) parts.push(shortHex(entry.userOpHash));
  if (entry.error) parts.push(entry.error.code !== undefined ? `${entry.error.name} ${entry.error.code}` : entry.error.name);
  if (entry.durationMs !== undefined) parts.push(formatDuration(entry.durationMs));
  return parts.join(' · ');
}

export function EntryDetails({ entry }: { entry: LedgerEntry }) {
  const receipt = entry.receipt;
  const balances = entry.balances;
  const nativeBefore = hexToBigInt(balances?.nativeBefore);
  const nativeAfter = hexToBigInt(balances?.nativeAfter);
  const json = useMemo(() => toJson(entry), [entry]);
  return (
    <Stack gap="3">
      <KeyValues
        items={[
          ['what happened', entry.error?.meaning ?? entry.note],
          ['what to do', entry.error?.action],
          ['chain', `${entry.chainName} (${entry.chainId})`],
          ['account', entry.account ? <HexWithCopy value={entry.account} /> : undefined],
          ['gas payer', entry.attribution ? <StatusText tone={entry.attribution.matchesDeclared === false ? 'orange' : entry.attribution.actualPayer === 'sponsored' ? 'accent' : 'gray'}>{entry.attribution.note}</StatusText> : entry.declaredPayer ? `declared ${entry.declaredPayer}` : undefined],
          ['user operation', entry.userOpHash ? <HexWithCopy value={entry.userOpHash} /> : undefined],
          ['transaction', entry.txHash ? <HexWithCopy value={entry.txHash} /> : undefined],
          ['block', receipt?.receipt?.blockNumber ? hexToBigInt(receipt.receipt.blockNumber)?.toString() : undefined],
          ['gas cost', receipt?.actualGasCost ? formatEth(hexToBigInt(receipt.actualGasCost), 6) : undefined],
          ['native balance', nativeBefore !== undefined || nativeAfter !== undefined ? `${formatEth(nativeBefore)} → ${formatEth(nativeAfter)}` : undefined],
          ['token balance', balances?.tokenBefore !== undefined || balances?.tokenAfter !== undefined ? `${balances?.tokenBefore ?? '—'} → ${balances?.tokenAfter ?? '—'} (raw units, ${shortHex(balances?.token)})` : undefined],
          ['took', formatDuration(entry.durationMs)],
        ]}
      />
      <Disclosure label="Technical details">
        <Stack gap="3">
          <KeyValues
            items={[
              ['method', entry.method],
              ['params', entry.params === undefined ? undefined : <CodeBlock value={entry.params} />],
              ['wallet origin', entry.walletOrigin],
              ['sender', receipt?.sender],
              ['paymaster', receipt?.paymaster],
              ['success', receipt?.success === undefined ? undefined : String(receipt.success)],
              ['revert reason', receipt?.reason],
              ['result', entry.result !== undefined && !entry.receipt ? <CodeBlock value={entry.result} /> : undefined],
              ['receipt', entry.receipt ? <CodeBlock value={entry.receipt} /> : undefined],
              ['error', entry.error ? <CodeBlock value={entry.error} /> : undefined],
            ]}
          />
          <HStack>
            <ClipboardRoot value={json}>
              <Button size="xs" variant="outline" asChild>
                <span>
                  <ClipboardIconButton aria-label="Copy entry" variant="ghost" size="2xs" /> Copy entry as JSON
                </span>
              </Button>
            </ClipboardRoot>
          </HStack>
        </Stack>
      </Disclosure>
    </Stack>
  );
}

export function OutcomeRow({ entry, defaultOpen = false }: { entry: LedgerEntry; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Collapsible.Root open={open} onOpenChange={(details) => setOpen(details.open)} borderWidth="1px" rounded="l2" bg="bg.subtle" data-testid="outcome-row" data-status={entry.status}>
      <Collapsible.Trigger asChild>
        <HStack as="button" w="full" textAlign="left" gap="3" px="3" py="2" flexWrap="wrap" cursor="pointer" alignItems="center">
          <EntryStatusText entry={entry} />
          <Text fontSize="sm" fontWeight="medium">
            {entry.label}
          </Text>
          <Mono muted>{summaryOf(entry)}</Mono>
          <Box ml="auto" color="fg.muted">
            {open ? <LuChevronDown /> : <LuChevronRight />}
          </Box>
        </HStack>
      </Collapsible.Trigger>
      <Collapsible.Content>
        <Box px="3" pb="3">
          <EntryDetails entry={entry} />
        </Box>
      </Collapsible.Content>
    </Collapsible.Root>
  );
}

/** The card's inline outcomes: one line each, folded; the reader opens what they need. */
export function Outcomes({ entries, title = 'Recent outcomes' }: { entries: LedgerEntry[]; title?: string }) {
  if (!entries.length) return null;
  return (
    <Stack gap="2">
      <Text fontSize="xs" fontWeight="medium" color="fg.muted" textTransform="uppercase" letterSpacing="wide">
        {title}
      </Text>
      {entries.map((entry) => (
        <OutcomeRow key={entry.id} entry={entry} />
      ))}
    </Stack>
  );
}

// ---- ActionPicker ----------------------------------------------------------------------------------

export function ActionPicker<T extends string>({ label, value, options, onChange, disabled }: { label?: string; value: T; options: Array<{ value: T; label: string }>; onChange: (value: T) => void; disabled?: boolean }) {
  return (
    <NativeSelect.Root size="md" width={{ base: 'full', md: '72' }} disabled={disabled}>
      <NativeSelect.Field aria-label={label ?? 'Action'} value={value} onChange={(event) => onChange(event.currentTarget.value as T)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </NativeSelect.Field>
      <NativeSelect.Indicator />
    </NativeSelect.Root>
  );
}

// ---- Disclosure ------------------------------------------------------------------------------------

export function Disclosure({ label, children, defaultOpen = false }: { label: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Collapsible.Root open={open} onOpenChange={(details) => setOpen(details.open)}>
      <Collapsible.Trigger asChild>
        <Button variant="ghost" size="sm" colorPalette="gray" px="1">
          {open ? <LuChevronDown /> : <LuChevronRight />} {label}
        </Button>
      </Collapsible.Trigger>
      <Collapsible.Content>
        <Box pt="3">{children}</Box>
      </Collapsible.Content>
    </Collapsible.Root>
  );
}
