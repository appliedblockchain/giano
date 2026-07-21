/**
 * Minimal pluggable logger used by the Giano provider.
 *
 * The default implementation is silent except for errors, so library consumers
 * never get debug noise in their console; pass a custom logger to
 * `createGianoProvider` to capture the other levels.
 */
export type GianoLogger = {
  debug: (message: string, data?: unknown) => void;
  warn: (message: string, data?: unknown) => void;
  error: (message: string, data?: unknown) => void;
};

export const defaultGianoLogger: GianoLogger = {
  debug: () => {},
  warn: () => {},
  error: (message, data) => {
    if (data === undefined) {
      console.error(message);
    } else {
      console.error(message, data);
    }
  },
};
