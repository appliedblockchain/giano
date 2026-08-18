import {
  Badge,
  Box,
  Card,
  chakra,
  ChakraProvider,
  Code,
  Heading,
  HStack,
  Portal,
  Spinner,
  Stack,
  Text,
  Toast,
  Toaster as ChakraToaster,
  createToaster,
} from '@chakra-ui/react';
import { useState, type ReactNode } from 'react';
import { system } from '../theme';

/**
 * The shared shell and primitives.
 *
 * Gathered in one file rather than a `components/ui/` tree of one-export snippets: there are four
 * of them, they are all small, and a reader looking for "how does a panel get its frame" should
 * find the answer in one place.
 */

export function Provider({ children }: { children: ReactNode }) {
  return <ChakraProvider value={system}>{children}</ChakraProvider>;
}

export const toaster = createToaster({ placement: 'bottom-end', pauseOnPageIdle: true });

export function Toaster() {
  return (
    <Portal>
      <ChakraToaster toaster={toaster} insetInline={{ mdDown: '4' }}>
        {(toast) => (
          <Toast.Root width={{ md: 'md' }}>
            {toast.type === 'loading' ? <Spinner size="sm" color="brand.solid" /> : <Toast.Indicator />}
            <Stack gap="1" flex="1" maxWidth="100%">
              {toast.title && <Toast.Title>{toast.title}</Toast.Title>}
              {toast.description && <Toast.Description>{toast.description}</Toast.Description>}
            </Stack>
            {toast.closable && <Toast.CloseTrigger />}
          </Toast.Root>
        )}
      </ChakraToaster>
    </Portal>
  );
}

/**
 * Every outcome is toasted *and* logged.
 *
 * A toast is transient and an operator who stepped away misses it; the console keeps the record,
 * including the full error, which is what someone pastes into an incident channel.
 */
export function notifySuccess(title: string, description?: string): void {
  toaster.create({ type: 'success', title, description });
  // eslint-disable-next-line no-console
  console.info(`[paymaster-admin] ${title}${description ? `: ${description}` : ''}`);
}

export function notifyError(title: string, error: unknown): string {
  const description = error instanceof Error ? error.message : String(error);
  toaster.create({ type: 'error', title, description, duration: 12_000 });
  // eslint-disable-next-line no-console
  console.error(`[paymaster-admin] ${title}`, error);
  return description;
}

export function SectionCard({ title, subtitle, action, children }: { title: string; subtitle?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <Card.Root bg="surface" shadow="sm" rounded="xl" borderWidth="1px" borderColor="border">
      <Card.Header pb="2">
        <HStack justify="space-between" align="flex-start" gap="4">
          <Box>
            <Heading size="md">{title}</Heading>
            {subtitle && (
              <Text fontSize="sm" color="fg.muted" mt="1">
                {subtitle}
              </Text>
            )}
          </Box>
          {action}
        </HStack>
      </Card.Header>
      <Card.Body pt="2">{children}</Card.Body>
    </Card.Root>
  );
}

/** A labelled figure. `mono` for anything the operator might compare digit by digit. */
export function Stat({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: 'default' | 'good' | 'bad' }) {
  const color = tone === 'good' ? 'accent.fg' : tone === 'bad' ? 'red.fg' : 'fg';
  return (
    <Box>
      <Text fontSize="xs" textTransform="uppercase" letterSpacing="wide" color="fg.muted">
        {label}
      </Text>
      <Text fontSize="2xl" fontWeight="semibold" fontFamily="mono" color={color} title={hint} lineHeight="1.2">
        {value}
      </Text>
      {hint && (
        <Text fontSize="xs" color="fg.muted" mt="0.5">
          {hint}
        </Text>
      )}
    </Box>
  );
}

const STATUS_TONE = {
  active: { colorPalette: 'green', label: 'active' },
  disabled: { colorPalette: 'gray', label: 'disabled' },
  'in-deficit': { colorPalette: 'red', label: 'in deficit' },
  unfunded: { colorPalette: 'orange', label: 'unfunded' },
} as const;

export function TenantStatusBadge({ status }: { status: keyof typeof STATUS_TONE }) {
  const tone = STATUS_TONE[status];
  return (
    <Badge colorPalette={tone.colorPalette} variant="subtle">
      {tone.label}
    </Badge>
  );
}

/** A monospace value. For anything on-chain prefer {@link Copyable}, which is also selectable. */
export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <Code fontSize="xs" title={title} variant="surface" px="1.5" py="0.5" rounded="sm">
      {children}
    </Code>
  );
}

/**
 * Copies text, falling back for browsers or contexts without the async clipboard.
 *
 * `navigator.clipboard` needs a secure context. `http://*.localhost` is one, so the devnet is
 * fine, but a console served over plain HTTP on another host would silently have no clipboard —
 * and an address that cannot be copied is the one thing this component exists to prevent.
 */
async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const field = document.createElement('textarea');
  field.value = value;
  field.setAttribute('readonly', '');
  field.style.position = 'fixed';
  field.style.opacity = '0';
  document.body.appendChild(field);
  field.select();
  try {
    if (!document.execCommand('copy')) throw new Error('the browser refused the copy');
  } finally {
    document.body.removeChild(field);
  }
}

/**
 * An on-chain identifier, shown in full and copied on click.
 *
 * Never abbreviated. An operator checking that a role holder is the timelock, or that a tenant
 * withdraws where they think it does, is comparing the whole value — and `0x1234…5678` hides
 * exactly the middle that distinguishes two addresses from the same deployer. Truncation saves
 * space at the cost of the one job this text has.
 */
export function Copyable({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await copyText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch (error) {
      notifyError('Could not copy to the clipboard', error);
    }
  };

  return (
    <CopyTrigger
      type="button"
      onClick={() => void copy()}
      title={`${label ? `${label}\n` : ''}${value}\n\nClick to copy`}
      aria-label={`Copy ${label ?? 'value'}: ${value}`}
    >
      {value}
      {copied && (
        <Box as="span" ml="2" color="accent.fg" fontWeight="medium">
          copied
        </Box>
      )}
    </CopyTrigger>
  );
}

/** A real `<button>` styled as inline code, so the whole value is one click target. */
const CopyTrigger = chakra('button', {
  base: {
    fontFamily: 'mono',
    fontSize: 'xs',
    bg: 'bg.muted',
    color: 'fg',
    px: '1.5',
    py: '0.5',
    rounded: 'sm',
    cursor: 'pointer',
    textAlign: 'left',
    wordBreak: 'break-all',
    lineHeight: 'short',
    transition: 'background 0.12s',
    _hover: { bg: 'bg.emphasized' },
    _focusVisible: { outline: '2px solid', outlineColor: 'brand.solid', outlineOffset: '1px' },
  },
});
