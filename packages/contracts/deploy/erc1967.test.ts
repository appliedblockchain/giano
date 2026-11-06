import assert from "node:assert/strict";
import { test } from "node:test";
import { getAddress, pad } from "viem";
import { implementationFromSlot } from "../erc1967";

const implementation = getAddress("0x326549c3600bfa31cb44213df0576ae79e70e4ac");

test("implementationFromSlot reads the low 20 bytes of the slot word, however a client returns it", () => {
	assert.equal(implementationFromSlot(pad(implementation)), implementation);
	assert.equal(
		implementationFromSlot(implementation.toLowerCase()),
		implementation,
	);
});

test("an empty or zero slot is no implementation", () => {
	for (const word of [undefined, null, "0x", pad("0x00"), "not hex"])
		assert.equal(implementationFromSlot(word), null, String(word));
});
