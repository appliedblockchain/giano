import { GianoError, GianoErrorOptions } from '../../giano-error'

export class SmartAccountDeploymentError extends GianoError {}

export class WaitForSmartAccountDeploymentError extends SmartAccountDeploymentError {}

export class WaitForSmartAccountDeploymentTimeoutError extends WaitForSmartAccountDeploymentError {
  constructor(
    /** The timeout value in milliseconds. */
    readonly timeout: number,
    options?: GianoErrorOptions,
  ) {
    const message = `Timeout waiting for smart account deployment after ${timeout}ms`
    super(message, options)
  }
}
