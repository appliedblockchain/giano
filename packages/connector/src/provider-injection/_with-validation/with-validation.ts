import { GianoProviderInjection, isGianoProviderInjection } from "../injection"
import { validationHooks } from './validation-hooks'

/**
 * Wraps the implementation of a Giano provider injection with validation hooks,
 * without modifying the original implementation instance.
 *
 * The wrapped implementation instance is returned, which includes the original
 * implementation instance as a property `implementation`.
 *
 * Optional hooks that are `undefined` are not wrapped, and stay `undefined` (so
 * code can check if this hook is to be used or not). This brings a edge case
 * limitation for optional hooks if the implementation is changed at runtime:
 * - a hook that was `undefined` is now defined; this wrapper will still have it
 *   `undefined` and will not call the new hook.
 * - a hook that was defined is now `undefined`; this wrapper will fail trying to
 *   call the hook in the implementation which is now `undefined`.
 *
 * @param implementation - The implementation of a Giano provider injection
 * @returns The wrapped implementation with validation hooks
 */
export const withValidation = <
  I extends GianoProviderInjection = GianoProviderInjection,
>(implementation: I) => {
  if (!isGianoProviderInjection(implementation)) {
    throw new Error('Invalid Giano provider injection implementation')
  }

  const injection = { implementation } as (
    I & { readonly implementation: I }
  )

  for (const key of Object.keys(validationHooks)) {
    if (implementation[key] === undefined) {
      injection[key] = undefined
      continue
    }
    injection[key] = validationHooks[key].bind(injection, key)
  }
  return injection
}
