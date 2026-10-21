/**
 * CREATE3 addressing through CreateX (https://github.com/pcaversaccio/createx).
 *
 * A canonical Giano address is a pure function of two inputs: the deployer EOA and a label. No
 * bytecode, compiler setting or constructor argument enters it, so a toolchain change, a new
 * compiler or a newer contract release never moves an address. That is the whole point of
 * deploying this way; see the "Canonical addresses" section of packages/contracts/README.md.
 *
 * The salt is CreateX's *permissioned* shape: `deployer (20 bytes) ‖ 0x00 ‖ 11 bytes`. CreateX
 * refuses that salt from any other sender, so nobody else can occupy a canonical address on a
 * chain we have not adopted yet. The `0x00` flag turns off CreateX's cross-chain redeploy
 * protection — on purpose, because the same label has to give the same address on every chain.
 * The 11 trailing bytes are the first 11 bytes of `keccak256(label)`.
 */
import {
	type Address,
	concat,
	getAddress,
	type Hex,
	keccak256,
	pad,
	slice,
	toBytes,
} from "viem";

/** CreateX, at the same address on every chain that has it. */
export const CREATEX_ADDRESS =
	"0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed" as const satisfies Address;

/**
 * keccak256 of the minimal proxy CreateX deploys with CREATE2 before the proxy CREATEs the real
 * contract (CreateX.sol, `computeCreate3Address`).
 */
const CREATE3_PROXY_INITCODE_HASH =
	"0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f" as const;

/** The salt `deployer` passes to CreateX for `label`. */
export function create3Salt(deployer: Address, label: string): Hex {
	return concat([
		getAddress(deployer),
		"0x00",
		slice(keccak256(toBytes(label)), 0, 11),
	]);
}

/**
 * The salt CreateX actually uses for a permissioned, non-chain-bound salt sent by its own
 * `deployer` (CreateX.sol `_guard`: `_efficientHash(bytes32(uint256(uint160(msg.sender))), salt)`).
 */
export function guardedSalt(deployer: Address, salt: Hex): Hex {
	return keccak256(concat([pad(getAddress(deployer)), salt]));
}

/** Where CreateX puts a CREATE3 deployment with this already-guarded salt. */
export function create3AddressFromGuardedSalt(
	guarded: Hex,
	createx: Address = CREATEX_ADDRESS,
): Address {
	const proxy = slice(
		keccak256(concat(["0xff", createx, guarded, CREATE3_PROXY_INITCODE_HASH])),
		12,
	);
	// The proxy's first CREATE: rlp([proxy, 1]) = 0xd6 0x94 <proxy> 0x01.
	return getAddress(slice(keccak256(concat(["0xd694", proxy, "0x01"])), 12));
}

/** The canonical address of `label` deployed by `deployer`, on any chain. */
export function create3Address(deployer: Address, label: string): Address {
	return create3AddressFromGuardedSalt(
		guardedSalt(deployer, create3Salt(deployer, label)),
	);
}
