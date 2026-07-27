import { toaster } from '../components/ui/toaster';
import { describeError } from './errors';

// Every user-facing outcome is both surfaced (toast) and logged to the console,
// so failures are always debuggable from the console.
export function notifySuccess(title: string, description?: string): void {
  console.info(`[giano-demo] ${title}${description ? `: ${description}` : ''}`);
  toaster.create({ type: 'success', title, description });
}

export function notifyInfo(title: string, description?: string): void {
  console.info(`[giano-demo] ${title}${description ? `: ${description}` : ''}`);
  toaster.create({ type: 'info', title, description });
}

/** Logs the raw error to the console and shows a (longer-lived) error toast. Returns the message. */
export function notifyError(title: string, error: unknown): string {
  const description = describeError(error);
  console.error(`[giano-demo] ${title}:`, error);
  toaster.create({ type: 'error', title, description, duration: 10000 });
  return description;
}
