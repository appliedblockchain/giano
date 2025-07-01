import type { GianoProviderInjection } from '@appliedblockchain/giano-connector';
import { createGianoInjection } from './giano-injection';
import { ServerStorage } from './demo-server-storage';

/**
 * DEMO: Create a Giano injection with server-side storage
 * @param userId - Unique identifier for the user
 * @param apiBaseUrl - Base URL for the storage API (defaults to current origin)
 *
 * ⚠️ This is for demonstration purposes only!
 * In production, you'd likely store passkey data differently (database, etc.)
 */
export function createGianoServerInjection(userId: string, apiBaseUrl = ''): GianoProviderInjection {
  const serverStorage = new ServerStorage(`${apiBaseUrl}/api/storage`, userId);
  return createGianoInjection(serverStorage);
}

/**
 * DEMO: Create server injection for a specific user
 *
 * ⚠️ This is for demonstration purposes only!
 */
export function createUserServerInjection(userId: string): GianoProviderInjection {
  return createGianoServerInjection(userId);
}
