import type {
	ManagementController,
	ManagementFlow,
	ManagementState,
} from "@appliedblockchain/giano-wallet-kit";
import { PasskeyDeviceGuidance } from "../PasskeyDeviceGuidance";
import {
	addedFromLabel,
	ChainProgressList,
	ChainsNotice,
	FlowShell,
	inputStyle,
	PairingQr,
	RefusalNotice,
} from "./shared";

export type AddVariant = "this-device" | "second-device";

/**
 * Renders the kit's `add` flow (WM-14, WM-18…WM-23). Every step — the claim code, the
 * fingerprint to compare, the per-chain progress — comes from the controller; this
 * component only draws it. Which entry point started the flow ('this device' vs 'another
 * device') is a copy decision, so it lives here, not in the kit.
 */
export function AddFlow({
	flow,
	state,
	actions,
	variant,
}: {
	flow: Extract<ManagementFlow, { type: "add" }>;
	state: ManagementState;
	actions: ManagementController;
	variant: AddVariant;
}) {
	const titles =
		variant === "this-device"
			? "Add a passkey on this device"
			: "Add a passkey on another device";

	if (flow.step === "preparing") {
		return (
			<FlowShell title={titles}>
				<p>
					<span className="spinner" /> Checking that this change is covered…
				</p>
				<div className="actions">
					<button type="button" onClick={() => actions.dismissFlow()}>
						Cancel
					</button>
				</div>
			</FlowShell>
		);
	}

	if (flow.step === "claim-code") {
		const formatted = `${flow.claimCode.slice(0, 4)}-${flow.claimCode.slice(4)}`;
		return (
			<FlowShell title="On your other device…">
				<p>
					1. Scan this code with the other device's camera. It opens{" "}
					<b>{window.location.origin}</b> with the code filled in.
				</p>
				<PairingQr url={flow.pairingUrl} />
				<p>
					Or open <b>{window.location.origin}</b> there, choose{" "}
					<b>“Add this device to an existing wallet”</b>, and enter:
				</p>
				<div
					className="data-box"
					style={{ fontSize: 26, textAlign: "center", letterSpacing: 3 }}
					data-testid="manage-claim-code"
				>
					{formatted}
				</div>
				<p>
					2. Create the passkey there, then compare the fingerprints. The code
					only routes the other device here — it cannot add anything by itself.
					It expires at {new Date(flow.expiresAt).toLocaleTimeString()}.
				</p>
				<p>
					<span className="spinner" /> Waiting for the other device…
				</p>
				<div className="actions">
					<button type="button" onClick={flow.cancel}>
						Cancel
					</button>
				</div>
			</FlowShell>
		);
	}

	if (flow.step === "confirm-fingerprint") {
		// WM-17/WM-20/WM-21: the consent screen shows the fingerprint of the key it is about
		// to sign for — recomputed by the kit from the key as received — BEFORE the
		// authorising signature's passkey prompt is raised.
		// A name is stored only when the user types one. Without it, the list shows the passkey by
		// its device and browser, like every other unnamed passkey, so the placeholder shows that.
		const nameInput = (
			<label style={{ fontSize: 13 }}>
				Name it (optional, you can rename later)
				<input
					value={flow.name}
					onChange={(event) => flow.setName(event.target.value)}
					placeholder={addedFromLabel(flow) ?? "e.g. My phone"}
					style={inputStyle}
					data-testid="manage-add-name"
				/>
			</label>
		);

		if (variant === "this-device") {
			return (
				<FlowShell title="Review: add this passkey">
					<p>
						A new passkey was created on this device. Approving adds it as an
						owner of your wallet, with full and equal control.
					</p>
					<div className="kv">
						<span className="k">Fingerprint</span>
						<span className="v" data-testid="manage-consent-fingerprint">
							{flow.fingerprint}
						</span>
					</div>
					<ChainsNotice chains={state.chains} />
					{nameInput}
					<div className="actions">
						<button type="button" className="danger" onClick={flow.decline}>
							Cancel
						</button>
						<button
							type="button"
							className="primary"
							onClick={flow.approve}
							data-testid="manage-add-approve"
						>
							Add passkey
						</button>
					</div>
				</FlowShell>
			);
		}

		return (
			<FlowShell title="Compare the fingerprints">
				<p>
					Your other device is showing a fingerprint for the passkey it just
					created. Approve <b>only if all four groups match</b> this one,
					character by character — the match is what stops anyone in the middle
					substituting their own key.
				</p>
				<div
					className="data-box"
					style={{ fontSize: 20, textAlign: "center", letterSpacing: 2 }}
					data-testid="manage-consent-fingerprint"
				>
					{flow.fingerprint}
				</div>
				{addedFromLabel(flow) ? (
					<div className="kv">
						<span className="k">Created on</span>
						<span className="v" data-testid="manage-consent-added-from">
							{addedFromLabel(flow)}
						</span>
					</div>
				) : null}
				<ChainsNotice chains={state.chains} />
				{nameInput}
				<div className="actions">
					<button
						type="button"
						className="danger"
						onClick={flow.decline}
						data-testid="manage-fingerprint-decline"
					>
						They don't match
					</button>
					<button
						type="button"
						className="primary"
						onClick={flow.approve}
						data-testid="manage-fingerprint-approve"
					>
						They match — add it
					</button>
				</div>
			</FlowShell>
		);
	}

	if (flow.step === "applying") {
		return (
			<FlowShell title="Adding the passkey…">
				<p>Confirm each network's passkey prompt. Progress per network:</p>
				<PasskeyDeviceGuidance />
				<ChainProgressList progress={flow.chains} />
			</FlowShell>
		);
	}

	if (flow.step === "declined") {
		return (
			<FlowShell title="Nothing was added">
				<p data-testid="manage-declined-note">
					The pending addition was declined and cannot be used. If the
					fingerprints did not match, the key offered to you was not the one
					your other device created — nothing was signed, and the attempt has
					been recorded.
				</p>
				<div className="actions">
					<button
						type="button"
						className="primary"
						onClick={() => actions.dismissFlow()}
						data-testid="manage-flow-done"
					>
						Back to the list
					</button>
				</div>
			</FlowShell>
		);
	}

	if (flow.step === "expired") {
		// WM-23: distinguishable from a network failure, with the action the user can take.
		return (
			<FlowShell title="The code expired">
				<p data-testid="manage-expired-note">
					Pending additions expire after a few minutes and cannot be resumed.
					Start again — the other device will need to create a fresh passkey.
				</p>
				<div className="actions">
					<button
						type="button"
						className="primary"
						onClick={() => actions.dismissFlow()}
						data-testid="manage-flow-done"
					>
						Back to the list
					</button>
				</div>
			</FlowShell>
		);
	}

	if (flow.step === "done" && flow.saveFailed) {
		// On-chain, but wallet-api has no record of the passkey, so the new device cannot sign in yet.
		return (
			<FlowShell title="Added, but not saved yet">
				<p data-testid="manage-save-failed">
					The passkey is now an owner of your wallet, but saving it to your
					account failed, so it cannot sign in yet. Try again; nothing is signed
					twice.
				</p>
				<ChainProgressList progress={flow.chains} />
				<div className="actions">
					<button type="button" onClick={() => actions.dismissFlow()}>
						Later
					</button>
					<button
						type="button"
						className="primary"
						onClick={flow.retrySave}
						data-testid="manage-retry-save"
					>
						Try again
					</button>
				</div>
			</FlowShell>
		);
	}

	if (flow.step === "done") {
		return (
			<FlowShell
				title={
					flow.ok
						? "Passkey added"
						: flow.appliedChainIds.length > 0
							? "Passkey added — attention needed"
							: "Nothing was added"
				}
			>
				{flow.refusal ? (
					<RefusalNotice
						reason={flow.refusal.reason}
						message={flow.refusal.message}
					/>
				) : null}
				<ChainProgressList progress={flow.chains} />
				{!flow.ok && flow.appliedChainIds.length > 0 ? (
					<p>
						The change is not complete on every network (WM-44) — the owner list
						will show the difference until it is reconciled.
					</p>
				) : null}
				{variant === "second-device" && flow.ok ? (
					<p>The other device can now sign in with its new passkey.</p>
				) : null}
				<div className="actions">
					<button
						type="button"
						className="primary"
						onClick={() => actions.dismissFlow()}
						data-testid="manage-flow-done"
					>
						Back to the list
					</button>
				</div>
			</FlowShell>
		);
	}

	// flow.step === 'error'
	return (
		<FlowShell title="Something went wrong">
			<div className="error" data-testid="manage-flow-error">
				{flow.message}
			</div>
			<div className="actions">
				<button type="button" onClick={() => actions.dismissFlow()}>
					Back
				</button>
			</div>
		</FlowShell>
	);
}
