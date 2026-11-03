/**
 * compileRelease against the committed releases. Needs the releases' solc (any `forge build`
 * installs it), so it runs as `pnpm test:releases`, not with the solc-free `test:deploy`.
 */
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Hex } from "viem";
import { releaseOf } from "../release-code";
import { listReleases, loadRelease } from "./release";
import { compileRelease } from "./release-compile";

for (const version of listReleases()) {
	describe(`release ${version}`, () => {
		const compiled = compileRelease(version);
		const names = (contract: keyof typeof compiled) =>
			compiled[contract]?.immutables.map((i) => i.name);

		test("reproduces every contract's creation code", () => {
			const release = loadRelease(version);
			for (const [name, { creationCode }] of Object.entries(
				release.contracts,
			)) {
				assert.equal(
					compiled[name as keyof typeof compiled]?.creationCode.toLowerCase(),
					creationCode.toLowerCase(),
					name,
				);
			}
		});

		test("reports the factory's implementation immutable", () => {
			assert.deepEqual(names("GianoSmartWalletFactory"), [
				"GianoSmartWalletFactory.implementation",
			]);
		});

		test("reports the UUPS self-address immutable of both implementations", () => {
			assert.deepEqual(names("GianoSmartWallet"), [
				"CallContextChecker.__self",
			]);
			assert.deepEqual(names("GianoPaymaster"), ["UUPSUpgradeable.__self"]);
		});

		/** `code` with every range of `name` set to `word` (32 bytes, hex without 0x). */
		const fill = (
			code: Hex,
			ranges: { start: number; length: number }[],
			word: string,
		) => {
			let out = code.toLowerCase();
			for (const { start, length } of ranges)
				out =
					out.slice(0, 2 + start * 2) +
					word +
					out.slice(2 + (start + length) * 2);
			return out as Hex;
		};
		const word = (address: string) =>
			address.slice(2).toLowerCase().padStart(64, "0");
		const A = "0x00000000000000000000000000000000000000aa";
		const B = "0x00000000000000000000000000000000000000bb";

		test("releaseOf requires __self to be the address the code was read from", () => {
			for (const name of ["GianoSmartWallet", "GianoPaymaster"] as const) {
				const { runtimeCode, immutables } = compiled[name] ?? assert.fail(name);
				const code = fill(runtimeCode, immutables[0].ranges, word(A));
				assert.equal(releaseOf(name, code, A)?.release, version, name);
				assert.equal(releaseOf(name, code)?.release, version, name);
				assert.equal(releaseOf(name, code, B), undefined, name);
			}
		});

		test("releaseOf refuses an immutable whose ranges hold different values", () => {
			const { runtimeCode, immutables } =
				compiled.GianoSmartWalletFactory ?? assert.fail("factory");
			const [first, ...rest] = immutables[0].ranges;
			const consistent = fill(runtimeCode, immutables[0].ranges, word(A));
			assert.equal(
				releaseOf("GianoSmartWalletFactory", consistent)?.release,
				version,
			);
			const split = fill(fill(runtimeCode, [first], word(B)), rest, word(A));
			assert.equal(releaseOf("GianoSmartWalletFactory", split), undefined);
		});

		test("every immutable range lies inside the runtime code and holds zeroes", () => {
			for (const [name, contract] of Object.entries(compiled)) {
				const size = (contract.runtimeCode.length - 2) / 2;
				for (const immutable of contract.immutables) {
					assert.ok(immutable.ranges.length > 0, `${name} ${immutable.name}`);
					for (const { start, length } of immutable.ranges) {
						assert.ok(start + length <= size, `${name} ${immutable.name}`);
						assert.match(
							contract.runtimeCode.slice(
								2 + start * 2,
								2 + (start + length) * 2,
							),
							/^0+$/,
						);
					}
				}
			}
		});
	});
}
