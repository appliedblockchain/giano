export type GianoErrorOptions = {
  cause?: unknown
}

/**
 * Base error class for all Giano-related errors.
 * 
 * Automatically handles proper prototype chain setup and error naming for subclasses.
 * Supports modern error chaining with the `cause` option for better debugging.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * throw new GianoError('Something went wrong')
 * 
 * // With error chaining
 * try {
 *   await someOperation()
 * } catch (originalError) {
 *   throw new GianoError('Operation failed', { cause: originalError })
 * }
 * 
 * // Creating custom error types (zero boilerplate)
 * export class GianoCustomError extends GianoError {}
 * 
 * // instanceof checks work correctly
 * try {
 *   throw new GianoCustomError('test')
 * } catch (error) {
 *   console.log(error instanceof GianoError)       // true
 *   console.log(error instanceof GianoCustomError) // true
 *   console.log(error.name)                        // "GianoCustomError"
 * }
 * ```
 */
export class GianoError extends Error {
  public readonly name: string
  public readonly cause?: unknown

  /**
   * Creates a new GianoError instance.
   * 
   * @param message - The error message
   * @param options - Additional options
   * @param options.cause - The underlying cause of this error (for error chaining)
   */
  constructor(message: string, options?: GianoErrorOptions) {
    super(message)
    this.name = this.constructor.name
    this.cause = options?.cause

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, this.constructor.prototype)

    // Capture stack trace if available (V8/Node.js only — not in the DOM lib types)
    const errorCtor = Error as unknown as { captureStackTrace?: (target: object, ctor: unknown) => void }
    if (errorCtor.captureStackTrace) {
      errorCtor.captureStackTrace(this, this.constructor)
    }
  }
}
