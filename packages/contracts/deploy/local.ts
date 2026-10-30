/**
 * Setup that only makes sense on a local anvil chain: the infrastructure a public chain already has
 * (CreateX, EntryPoint v0.9), and impersonating the canonical deployer so no key is needed.
 */
import { createRequire } from "node:module";
import {
	type Address,
	concat,
	type Hex,
	keccak256,
	type PublicClient,
	parseEther,
	type TestClient,
} from "viem";
import { isCanonicalEntryPointCode } from "../entrypoint";
import { ENTRY_POINT_V09 } from "./config";
import { CREATEX_ADDRESS } from "./create3";
import { presignedDeployment } from "./createx";
import { ARACHNID_PRESIGNED_TX, ARACHNID_PROXY, ARACHNID_SIGNER } from "./p256";

const require = createRequire(import.meta.url);

/**
 * CreateX through its own keyless deployment transaction (pre-EIP-155, so valid on any chain id),
 * which is what puts it at the same address on every public chain.
 */
export async function installCreateX(
	publicClient: PublicClient,
	testClient: TestClient,
	log: (line: string) => void,
): Promise<void> {
	const existing = await publicClient.getCode({ address: CREATEX_ADDRESS });
	if (existing && existing !== "0x") {
		log(`  = CreateX already at ${CREATEX_ADDRESS}`);
		return;
	}
	const { signer, gasLimit, gasPriceWei, rawTransaction } = presignedDeployment;
	await testClient.setBalance({
		address: signer,
		value: BigInt(gasLimit) * BigInt(gasPriceWei),
	});
	const hash = await publicClient.request({
		method: "eth_sendRawTransaction",
		params: [rawTransaction],
	});
	const receipt = await publicClient.waitForTransactionReceipt({ hash });
	if (receipt.status !== "success")
		throw new Error(`CreateX's presigned deployment reverted (${hash})`);
	const code = await publicClient.getCode({ address: CREATEX_ADDRESS });
	if (!code || code === "0x")
		throw new Error(
			`CreateX's presigned deployment did not land at ${CREATEX_ADDRESS}`,
		);
	log(`  + CreateX at ${CREATEX_ADDRESS}`);
}

/** The salt EntryPoint v0.9 was deployed with through the Arachnid proxy on every public chain. */
const ENTRY_POINT_V09_SALT: Hex =
	"0x7702864008ddeab30aa67b7adc3d2653bc8d162714b1fe8fe4582df814f3bf61";

/** The Arachnid CREATE2 proxy, through its keyless deployment if the chain lacks it. */
async function ensureArachnidProxy(
	publicClient: PublicClient,
	testClient: TestClient,
): Promise<void> {
	const code = await publicClient.getCode({ address: ARACHNID_PROXY });
	if (code && code !== "0x") return;
	await testClient.setBalance({
		address: ARACHNID_SIGNER,
		value: parseEther("0.1"),
	});
	const hash = await publicClient.request({
		method: "eth_sendRawTransaction",
		params: [ARACHNID_PRESIGNED_TX],
	});
	await publicClient.waitForTransactionReceipt({ hash });
}

/**
 * EntryPoint v0.9 at its canonical address, deployed the way it was on every public chain: its
 * published creation code through the Arachnid proxy with its published salt. Not a code copy —
 * the constructor deploys the SenderCreator that account creation goes through and records its
 * address in an immutable, so only a real deployment yields a working EntryPoint.
 */
export async function installEntryPoint(
	publicClient: PublicClient,
	testClient: TestClient,
	from: Address,
	log: (line: string) => void,
): Promise<void> {
	const existing = await publicClient.getCode({ address: ENTRY_POINT_V09 });
	if (existing && existing !== "0x") {
		if (!isCanonicalEntryPointCode(existing, await publicClient.getChainId()))
			throw new Error("EntryPoint v0.9 code mismatch");
		log(`  = EntryPoint v0.9 already at ${ENTRY_POINT_V09}`);
		return;
	}
	await ensureArachnidProxy(publicClient, testClient);
	const artifact =
		require("@account-abstraction/contracts/artifacts/EntryPoint.json") as {
			bytecode: Hex;
		};
	// Top up only: `from` is usually a funded anvil account, and setBalance replaces a balance.
	if ((await publicClient.getBalance({ address: from })) < parseEther("1"))
		await testClient.setBalance({ address: from, value: parseEther("1") });
	const hash = await testClient.sendUnsignedTransaction({
		from,
		to: ARACHNID_PROXY,
		data: concat([ENTRY_POINT_V09_SALT, artifact.bytecode]),
		gas: 8_000_000n,
	});
	const receipt = await publicClient.waitForTransactionReceipt({ hash });
	const code = await publicClient.getCode({ address: ENTRY_POINT_V09 });
	if (receipt.status !== "success" || !code || code === "0x") {
		throw new Error(
			`EntryPoint v0.9 did not land at ${ENTRY_POINT_V09} (${hash}); the @account-abstraction/contracts artifact may not be the canonical build`,
		);
	}
	log(
		`  + EntryPoint v0.9 at ${ENTRY_POINT_V09} (${keccak256(code).slice(0, 10)}…)`,
	);
}

/** Lets eth_sendTransaction from `address` succeed without its key, and funds it. */
export async function impersonate(
	testClient: TestClient,
	address: Address,
): Promise<void> {
	await testClient.impersonateAccount({ address });
	await testClient.setBalance({ address, value: 10n ** 21n });
}
