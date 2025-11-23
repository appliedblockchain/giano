import type { GianoProviderInjection } from '@appliedblockchain/giano-connector';
import { createGianoInjection } from './giano-injection';
import { ServerStorage } from './storage-implementations';

export type CreateGianoServerInjectionOptions = {
  /** Base URL for the storage API (defaults to current origin) */
  apiBaseUrl?: string;
  /** Whether to enable backend user operation submission (defaults to true) */
  enableBackendSubmission?: boolean;
};

/**
 * DEMO: Create a Giano injection with server-side storage
 * @param userId - Unique identifier for the user
 * @param options - Configuration options for the server injection
 *
 * ⚠️ This is for demonstration purposes only!
 * In production, you'd likely store passkey data differently (database, etc.)
 */
export function createGianoServerInjection(
  userId: string,
  options: CreateGianoServerInjectionOptions = {},
): GianoProviderInjection {
  const { apiBaseUrl = '', enableBackendSubmission = true } = options;
  const serverStorage = new ServerStorage(`${apiBaseUrl}/api/storage`, userId);
  return createGianoInjection({
    storage: serverStorage,
    enableBackendSubmission,
  });
}

/**
 * DEMO: Create server injection for a specific user
 *
 * ⚠️ This is for demonstration purposes only!
 */
export function createUserServerInjection(
  userId: string,
  options: CreateGianoServerInjectionOptions = {},
): GianoProviderInjection {
  return createGianoServerInjection(userId, options);
}
