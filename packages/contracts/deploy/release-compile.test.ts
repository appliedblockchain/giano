/**
 * compileRelease against the committed releases. Needs the releases' solc (any `forge build`
 * installs it), so it runs as `pnpm test:releases`, not with the solc-free `test:deploy`.
 */
import assert from "node:assert/strict";
import { describe, test } from "node:test";
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
