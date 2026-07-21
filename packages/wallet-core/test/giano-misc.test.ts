import { afterEach, describe, expect, it, vi } from 'vitest';
import { GianoEntryPointAddress, GianoEntryPointVersion } from '../src/giano-entry-point';
import { GianoError } from '../src/giano-error';
import { defaultGianoLogger } from '../src/logger';

describe('GianoError', () => {
  it('sets name to the constructor name and carries the cause', () => {
    const cause = new Error('root');
    const error = new GianoError('boom', { cause });
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(GianoError);
    expect(error.name).toBe('GianoError');
    expect(error.message).toBe('boom');
    expect(error.cause).toBe(cause);
    expect(typeof error.stack).toBe('string');
  });

  it('names subclasses after their own constructor and keeps instanceof', () => {
    class MyError extends GianoError {}
    const error = new MyError('nope');
    expect(error.name).toBe('MyError');
    expect(error).toBeInstanceOf(GianoError);
    expect(error).toBeInstanceOf(MyError);
    expect(error.cause).toBeUndefined();
  });
});

describe('defaultGianoLogger', () => {
  afterEach(() => vi.restoreAllMocks());

  it('is silent for debug and warn', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    defaultGianoLogger.debug('d', { a: 1 });
    defaultGianoLogger.warn('w');
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('logs errors, with and without data', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    defaultGianoLogger.error('just message');
    defaultGianoLogger.error('with data', { code: 1 });
    expect(errorSpy).toHaveBeenNthCalledWith(1, 'just message');
    expect(errorSpy).toHaveBeenNthCalledWith(2, 'with data', { code: 1 });
  });
});

describe('giano entry point constants', () => {
  it('pins EntryPoint v0.7', () => {
    expect(GianoEntryPointVersion).toBe('0.7');
    expect(GianoEntryPointAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});
