export type AssertHexBaseOptions = {
  descriptor?: string
}

export type AssertHexDigitsOptions = AssertHexBaseOptions & {
  digits: number
  bytes?: never
}

export type AssertHexBytesOptions = AssertHexBaseOptions & {
  bytes: number
  digits?: never
}

export type AssertHexOptions = (
  | AssertHexBaseOptions
  | AssertHexDigitsOptions
  | AssertHexBytesOptions
)
