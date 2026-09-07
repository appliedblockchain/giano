import type { WriteResult } from '@appliedblockchain/giano-paymaster-sdk';
import { useCallback, useState } from 'react';
import { notifyError, notifySuccess } from '../components/ui';

/**
 * The write lifecycle, in one place.
 *
 * Submission and confirmation are shown separately: the SDK returns the hash as soon as the
 * transaction is accepted, and on a slow chain a console that only speaks once it is mined looks
 * frozen for a minute. The refresh runs after the receipt, because that is the first moment a
 * re-read would actually show the change.
 *
 * Refusals arrive already translated — "you do not hold FEE_COLLECTOR_ROLE" rather than an ABI
 * trace — so they are surfaced verbatim rather than reworded here.
 */
export function useWrite(refresh: () => Promise<void>) {
  const [pending, setPending] = useState<string>();

  const run = useCallback(
    async (label: string, send: () => Promise<WriteResult>): Promise<boolean> => {
      setPending(label);
      try {
        const result = await send();
        notifySuccess(`${label} submitted`, result.hash);
        await result.wait();
        notifySuccess(`${label} confirmed`);
        await refresh();
        return true;
      } catch (error) {
        notifyError(`Could not ${label.toLowerCase()}`, error);
        return false;
      } finally {
        setPending(undefined);
      }
    },
    [refresh],
  );

  return { run, pending, isPending: (label: string) => pending === label, busy: pending !== undefined };
}
