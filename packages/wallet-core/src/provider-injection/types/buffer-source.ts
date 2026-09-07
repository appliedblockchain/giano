export const isBufferSource = (value: unknown): value is BufferSource => {
  return value instanceof ArrayBuffer ||
    value instanceof Int8Array ||
    value instanceof Uint8Array ||
    value instanceof Uint8ClampedArray ||
    value instanceof Int16Array ||
    value instanceof Uint16Array ||
    value instanceof Int32Array ||
    value instanceof Uint32Array ||
    value instanceof Float32Array ||
    value instanceof Float64Array ||
    value instanceof BigInt64Array ||
    value instanceof BigUint64Array ||
    value instanceof DataView
}

export function isNonEmptyBufferSource(value: unknown): value is BufferSource {
  return isBufferSource(value) && value.byteLength > 0
}

export function assertNonEmptyBufferSource(
  value: unknown,
  options?: { descriptor?: string }
): asserts value is BufferSource {
  if (!isNonEmptyBufferSource(value)) {
    const errorMessage = options?.descriptor
      ? `\`${options.descriptor}\` must be a non-empty BufferSource`
      : 'Must be a non-empty BufferSource'

    throw new Error(errorMessage)
  }
}
