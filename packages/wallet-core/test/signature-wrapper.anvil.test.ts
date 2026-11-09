/**
 * Pins the `SignatureWrapper` wire format between this SDK and the released contract.
 *
 * `wrapSignature` encodes `(bytes ownerBytes, bytes signatureData)`, and `GianoSmartWallet`
 * decodes exactly that struct. The other tests check each side alone: the unit tests decode the
 * SDK's output with their own copy of the ABI, and the Foundry tests build the wrapper in
 * Solidity. This test runs the real SDK against the real contract, so it fails if the two ever
 * diverge (RFC: Multi-Ownership Support in Giano SDK, §3.3).
 *
 * The signers are secondary owners: added with `addOwnerAddress` / `addOwnerPublicKey` after
 * deployment, so they are not in the factory salt. That is the multi-ownership case the RFC is
 * about. The contracts come from the latest committed release (`packages/contracts/releases`),
 * which is the bytecode that is actually deployed, so no Solidity compiler is needed.
 *
 * Needs `anvil` on the PATH. Without it the suite is skipped locally but fails in CI.
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import {
	gianoSmartWalletAbi,
	gianoSmartWalletFactoryAbi,
} from "@appliedblockchain/giano-contracts";
import {
	type Address,
	createPublicClient,
	createWalletClient,
	decodeAbiParameters,
	encodeAbiParameters,
	encodeDeployData,
	type Hex,
	hashMessage,
	http,
	type PublicClient,
	pad,
	slice,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { toGianoSmartAccount } from "../src/account";
import { createWebAuthnOwner } from "./helpers";
import {
	type InstalledWebAuthnMock,
	installWebAuthnMock,
} from "./webauthn-mock";

/** Anvil's default accounts. Never used anywhere real. */
const KEYS = {
	primary: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
	secondary:
		"0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
	stranger:
		"0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
} as const;

/** ERC-1271 `isValidSignature` success value. */
const ERC1271_MAGIC = "0x1626ba7e";

const anvilAvailable = spawnSync("anvil", ["--version"]).status === 0;

const RELEASES_DIR = new URL("../../contracts/releases/", import.meta.url);

/** The creation code of the newest release under `packages/contracts/releases`. */
function latestReleaseContracts(): {
	version: string;
	wallet: Hex;
	factory: Hex;
} {
	const versions = readdirSync(RELEASES_DIR)
		.filter((entry) => /^v\d+$/.test(entry))
		.sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
	const version = versions.at(-1);
	if (!version) throw new Error(`no release under ${RELEASES_DIR.pathname}`);
	const release = JSON.parse(
		readFileSync(new URL(`${version}/release.json`, RELEASES_DIR), "utf8"),
	) as {
		contracts: Record<string, { creationCode: Hex }>;
	};
	return {
		version,
		wallet: release.contracts.GianoSmartWallet.creationCode,
		factory: release.contracts.GianoSmartWalletFactory.creationCode,
	};
}

async function freePort(): Promise<number> {
	const server = createServer();
	await new Promise<void>((resolve) =>
		server.listen(0, "127.0.0.1", () => resolve()),
	);
	const address = server.address();
	await new Promise<void>((resolve) => server.close(() => resolve()));
	if (!address || typeof address === "string") throw new Error("no free port");
	return address.port;
}

describe.skipIf(!anvilAvailable && !process.env.CI)(
	"SignatureWrapper wire format against the released GianoSmartWallet",
	() => {
		const release = latestReleaseContracts();
		const primary = privateKeyToAccount(KEYS.primary);
		const secondary = privateKeyToAccount(KEYS.secondary);
		const stranger = privateKeyToAccount(KEYS.stranger);

		let anvil: ChildProcess | undefined;
		let mock: InstalledWebAuthnMock;
		let client: PublicClient;
		let factory: Address;
		let wallet: Address;
		let passkeyOwner: Awaited<ReturnType<typeof createWebAuthnOwner>>["owner"];

		/** `isValidSignature` on the deployed wallet; a revert counts as a rejection. */
		async function isValidSignature(hash: Hex, signature: Hex) {
			try {
				return await client.readContract({
					address: wallet,
					abi: gianoSmartWalletAbi,
					functionName: "isValidSignature",
					args: [hash, signature],
				});
			} catch {
				return "reverted";
			}
		}

		beforeAll(async () => {
			mock = installWebAuthnMock();
			({ owner: passkeyOwner } = await createWebAuthnOwner(mock.authenticator));

			const port = await freePort();
			let spawnError: Error | undefined;
			anvil = spawn(
				"anvil",
				["--host", "127.0.0.1", "--port", String(port), "--silent"],
				{ stdio: "ignore" },
			);
			anvil.on("error", (error) => {
				spawnError = error;
			});

			const transport = http(`http://127.0.0.1:${port}`, { retryCount: 0 });
			client = createPublicClient({
				chain: foundry,
				transport,
			}) as PublicClient;
			for (let i = 0; ; i++) {
				if (spawnError) throw spawnError;
				try {
					await client.getChainId();
					break;
				} catch (error) {
					if (i >= 50) throw error;
					await new Promise((resolve) => setTimeout(resolve, 100));
				}
			}

			const deployer = createWalletClient({
				account: primary,
				chain: foundry,
				transport,
			});
			const deploy = async (data: Hex) => {
				const hash = await deployer.sendTransaction({ data });
				const receipt = await client.waitForTransactionReceipt({ hash });
				if (!receipt.contractAddress)
					throw new Error(`deployment failed (${hash})`);
				return receipt.contractAddress;
			};
			const write = async (
				request: Parameters<typeof deployer.writeContract>[0],
			) => {
				const hash = await deployer.writeContract(request);
				const receipt = await client.waitForTransactionReceipt({ hash });
				if (receipt.status !== "success")
					throw new Error(`transaction reverted (${hash})`);
			};

			const implementation = await deploy(release.wallet);
			factory = await deploy(
				encodeDeployData({
					abi: gianoSmartWalletFactoryAbi,
					bytecode: release.factory,
					args: [implementation],
				}),
			);

			// The account is created with the primary owner only: the secondary owners are not in
			// the factory salt, so the SDK must be told the account address.
			const initialOwners = [pad(primary.address)];
			wallet = await client.readContract({
				address: factory,
				abi: gianoSmartWalletFactoryAbi,
				functionName: "getAddress",
				args: [initialOwners, 0n],
			});
			await write({
				address: factory,
				abi: gianoSmartWalletFactoryAbi,
				functionName: "createAccount",
				args: [initialOwners, 0n],
			});

			// The primary owner is an EOA, so it adds the secondary owners by calling the wallet directly.
			await write({
				address: wallet,
				abi: gianoSmartWalletAbi,
				functionName: "addOwnerAddress",
				args: [secondary.address],
			});
			await write({
				address: wallet,
				abi: gianoSmartWalletAbi,
				functionName: "addOwnerPublicKey",
				args: [
					slice(passkeyOwner.publicKey, 0, 32),
					slice(passkeyOwner.publicKey, 32, 64),
				],
			});
		}, 60_000);

		afterAll(() => {
			anvil?.kill();
			mock?.uninstall();
		});

		it("the secondary owners are on-chain and outside the factory salt", async () => {
			const read = (index: bigint) =>
				client.readContract({
					address: wallet,
					abi: gianoSmartWalletAbi,
					functionName: "ownerAtIndex",
					args: [index],
				});
			expect(await read(1n)).toBe(pad(secondary.address).toLowerCase());
			expect(await read(2n)).toBe(passkeyOwner.publicKey.toLowerCase());
		});

		it("a secondary address owner's SDK signature passes isValidSignature", async () => {
			const account = await toGianoSmartAccount({
				client,
				address: wallet,
				owners: [secondary],
				factoryAddress: factory,
			});
			const message = "signature wrapper: address owner";
			const signature = await account.signMessage({ message });
			expect(await isValidSignature(hashMessage(message), signature)).toBe(
				ERC1271_MAGIC,
			);
		});

		it("a secondary passkey owner's SDK signature passes isValidSignature", async () => {
			const account = await toGianoSmartAccount({
				client,
				address: wallet,
				owners: [passkeyOwner],
				factoryAddress: factory,
			});
			const message = "signature wrapper: passkey owner";
			const signature = await account.signMessage({ message });
			expect(await isValidSignature(hashMessage(message), signature)).toBe(
				ERC1271_MAGIC,
			);
		});

		it("rejects a signature from a key that is not an owner", async () => {
			const account = await toGianoSmartAccount({
				client,
				address: wallet,
				owners: [stranger],
				factoryAddress: factory,
			});
			const message = "signature wrapper: stranger";
			const signature = await account.signMessage({ message });
			expect(await isValidSignature(hashMessage(message), signature)).not.toBe(
				ERC1271_MAGIC,
			);
		});

		it("rejects the old (uint8 ownerIndex, bytes) wrapper", async () => {
			// Same owner and the same inner signature, in the format the RFC asks about. The contract
			// must refuse it; if it ever accepted it, the wire format would have changed.
			const account = await toGianoSmartAccount({
				client,
				address: wallet,
				owners: [secondary],
				factoryAddress: factory,
			});
			const message = "signature wrapper: old format";
			const current = await account.signMessage({ message });
			const [{ signatureData }] = decodeAbiParameters(
				[
					{
						type: "tuple",
						components: [
							{ name: "ownerBytes", type: "bytes" },
							{ name: "signatureData", type: "bytes" },
						],
					},
				],
				current,
			);
			const oldFormat = encodeAbiParameters(
				[
					{
						type: "tuple",
						components: [
							{ name: "ownerIndex", type: "uint8" },
							{ name: "signatureData", type: "bytes" },
						],
					},
				],
				[{ ownerIndex: 1, signatureData }],
			);
			expect(await isValidSignature(hashMessage(message), oldFormat)).not.toBe(
				ERC1271_MAGIC,
			);
		});
	},
);
