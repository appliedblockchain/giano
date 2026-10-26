/** CreateX: its ABI and, for local chains, its keyless deployment (vendor/createx/README.md). */
import * as fs from "node:fs";
import * as path from "node:path";
import type { Abi, Address, Hex } from "viem";
import { CREATEX_ADDRESS } from "./create3";

const vendor = path.resolve(import.meta.dirname, "..", "vendor", "createx");

export const createxAbi = (
	JSON.parse(fs.readFileSync(path.join(vendor, "CreateX.json"), "utf8")) as {
		abi: Abi;
	}
).abi;

export type PresignedDeployment = {
	createx: Address;
	signer: Address;
	gasLimit: number;
	gasPriceWei: string;
	rawTransaction: Hex;
};

export const presignedDeployment = JSON.parse(
	fs.readFileSync(path.join(vendor, "presigned-deployment.json"), "utf8"),
) as PresignedDeployment;

if (
	presignedDeployment.createx.toLowerCase() !== CREATEX_ADDRESS.toLowerCase()
) {
	throw new Error(
		"vendor/createx/presigned-deployment.json names a different CreateX address",
	);
}
