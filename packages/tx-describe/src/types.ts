import type { Descriptor } from '@ethereum-sourcify/clear-signing';

/**
 * A transaction as an application hands it to a wallet: the plain `eth_sendTransaction`
 * request, before any account abstraction wraps it. Values may arrive as hex strings, decimal
 * strings, numbers or bigints; anything else yields an `unknown` result rather than a throw.
 */
export type TransactionInput = {
  chainId: number;
  to?: string | null;
  value?: bigint | string | number | null;
  data?: string | null;
};

/**
 * A mapping is an ERC-7730 descriptor (https://eips.ethereum.org/EIPS/eip-7730) for one
 * contract: `context.contract.deployments` binds it to `(chainId, address)` pairs and
 * `display.formats` explains each function. One descriptor therefore covers every call of a
 * function on that contract. The ABI MUST be inline (`context.contract.abi` as an array): the
 * library never fetches anything.
 */
export type Mapping = Descriptor;

export type NativeCurrency = { symbol: string; decimals: number; name?: string };

export type TokenInfo = { symbol: string; decimals: number; name?: string };

/**
 * Resolves an ERC-20's symbol and decimals. The library never reads the chain, so the caller
 * supplies this; `null` (or a rejection) renders the amount unscaled with a warning.
 */
export type TokenResolver = (chainId: number, tokenAddress: string) => Promise<TokenInfo | null>;

export type DescribeOptions = {
  /** Caller-supplied mappings; the first whose deployments include `(chainId, to)` is used. */
  mappings?: readonly Mapping[];
  /** Built-in generic ERC-20 / ERC-721 mappings are used when nothing else matches. Default true. */
  builtins?: boolean;
  /** The chain's native currency for `value` formatting. Default `{ symbol: 'ETH', decimals: 18 }`. */
  nativeCurrency?: NativeCurrency;
  resolveToken?: TokenResolver;
};

export type DescriptionSource =
  /** A caller-supplied mapping bound to this chain and contract. */
  | 'mapping'
  /** A built-in generic mapping matched by selector alone; the contract is not verified. */
  | 'generic'
  /** A native-currency transfer (no calldata); needs no mapping. */
  | 'native';

export type DescriptionWarningCode =
  /** A built-in generic mapping was used: the contract has not been confirmed to implement it. */
  | 'generic-interface'
  /** A token amount could not be scaled because the token's metadata was not resolved. */
  | 'token-unresolved'
  /** The mapping defines an interpolated intent but it could not be filled in. */
  | 'interpolation-failed'
  /** The caller's mapping set could not be loaded; only built-ins were available. Set by callers. */
  | 'mappings-unavailable'
  /** Anything else the formatting engine reported that did not prevent a description. */
  | 'engine';

export type DescriptionWarning = { code: DescriptionWarningCode; message: string };

export type FieldKind = 'address' | 'amount' | 'token-amount' | 'text';

export type DescriptionField = {
  label: string;
  /** Display value: shortened checksummed address, scaled amount with symbol, or text. */
  value: string;
  kind: FieldKind;
  /** Full checksummed address for `address` fields; the token contract for `token-amount`. */
  address?: string;
};

export type RawTransaction = { to: string | null; value: string; data: string };

export type DescribedTransaction = {
  kind: 'described';
  /** One sentence with values filled in, e.g. "Send 10.5 USDC to 0x1234…abcd". */
  intent: string;
  fields: DescriptionField[];
  source: DescriptionSource;
  /** Checksummed target of the call. */
  contract: string;
  /** Human-readable signature of the matched function; null for a native transfer. */
  functionSignature: string | null;
  /** 4-byte selector of the call; null for a native transfer. */
  selector: string | null;
  metadata?: { contractName?: string; owner?: string };
  warnings: DescriptionWarning[];
  raw: RawTransaction;
};

export type UnknownReason =
  /** No mapping (caller-supplied or built-in) covers this chain, contract and selector. */
  | 'no-mapping'
  /** A mapping matched but the calldata does not fit the function, or the input is malformed. */
  | 'decode-failed'
  /** The transaction has no `to`: it deploys a contract. */
  | 'contract-creation';

export type UnknownTransaction = {
  kind: 'unknown';
  reason: UnknownReason;
  selector: string | null;
  contract: string | null;
  warnings: DescriptionWarning[];
  raw: RawTransaction;
};

export type TransactionDescription = DescribedTransaction | UnknownTransaction;

export type ValidationIssue = { path: string; message: string };

export type ValidationResult = { ok: true; issues: [] } | { ok: false; issues: ValidationIssue[] };
