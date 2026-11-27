import type {
	ManagementController,
	ManagementNotice,
	OwnerRow,
} from "@appliedblockchain/giano-wallet-kit";
import { claimCodeFromUrl } from "@appliedblockchain/giano-wallet-kit";
import { useManagement } from "@appliedblockchain/giano-wallet-kit/react";
import { useEffect, useRef, useState } from "react";
import { AddFlow, type AddVariant } from "./manage/AddFlow";
import { AddressFlow } from "./manage/AddressFlow";
import { ClaimFlow } from "./manage/ClaimFlow";
import { RemoveFlow } from "./manage/RemoveFlow";
import { addedFromLabel, RefusalNotice } from "./manage/shared";
import { PasskeyDeviceGuidance } from "./PasskeyDeviceGuidance";

/**
 * The wallet-management interface (WM-01…WM-11), rendered over the kit's headless
 * controller (WK-16, WK-30): the owner set read from the chain, reconciled against the
 * registry — with divergence shown rather than hidden — plus the add and remove flows.
 * Everything ordering-critical (chain-before-registry, index re-reads, fingerprint
 * recompute, the last-owner guard) is the kit's; this file is pixels.
 *
 * Reached two ways with the same capabilities (WM-56): standalone on the wallet origin,
 * and from an application through `giano_openWalletManagement` (then `onClose` resolves
 * the transport request with nothing, WM-40).
 */
export function Manage({ onClose }: { onClose?: () => void }) {
	const { state, flow, actions } = useManagement();
	// Which entry point started the add flow is a copy decision, so it lives in the view.
	const [addVariant, setAddVariant] = useState<AddVariant>("this-device");

	// PS-2: a pairing link (a scanned QR code) opens the wallet origin with the claim code in its
	// fragment. Start the claim with it filled in; the user still continues before a passkey is made.
	// Only on the wallet origin's own page, never in an application's popup.
	const claimedFromLink = useRef(false);
	useEffect(() => {
		if (claimedFromLink.current || onClose) return;
		const code = claimCodeFromUrl(window.location.href);
		if (!code) return;
		claimedFromLink.current = true;
		// The code has done its job: keep it out of the address bar and the history.
		window.history.replaceState(
			null,
			"",
			window.location.pathname + window.location.search,
		);
		actions.startClaimOnThisDevice(code);
	}, [actions, onClose]);

	// ── Active flow ──────────────────────────────────────────────────────────────────
	if (flow) {
		if (flow.type === "add")
			return (
				<AddFlow
					flow={flow}
					state={state}
					actions={actions}
					variant={addVariant}
				/>
			);
		if (flow.type === "address")
			return <AddressFlow flow={flow} state={state} actions={actions} />;
		if (flow.type === "remove")
			return <RemoveFlow flow={flow} state={state} actions={actions} />;
		if (flow.type === "claim")
			return <ClaimFlow flow={flow} actions={actions} />;
		// flow.type === 'refused': a sponsorship refusal met before any passkey prompt (WM-68)
		return (
			<>
				<RefusalNotice reason={flow.reason} message={flow.message} />
				<div className="actions">
					<button type="button" onClick={flow.back}>
						Back
					</button>
				</div>
			</>
		);
	}

	// ── Signed out (WM-57): offer sign-in rather than failing ────────────────────────
	if (state.view === "signed-out") {
		return (
			<>
				<PasskeyDeviceGuidance />
				<div className="card">
					<h2>Manage your wallet</h2>
					{state.notice ? (
						<p className="note" data-testid="manage-notice">
							{NOTICES[state.notice]}
						</p>
					) : null}
					<p>
						Sign in to see and control the passkeys and accounts that can act on
						your wallet.
					</p>
					{state.error ? (
						<div className="error" data-testid="manage-error">
							{state.error}
						</div>
					) : null}
				</div>
				<div className="actions" style={{ flexDirection: "column" }}>
					<button
						type="button"
						className="primary"
						onClick={() => void actions.signIn()}
						disabled={state.busy}
						data-testid="manage-sign-in"
					>
						{state.busy ? "Waiting for passkey…" : "Sign in with passkey"}
					</button>
					<button
						type="button"
						onClick={() => actions.startClaimOnThisDevice()}
						disabled={state.busy}
						data-testid="manage-claim-entry"
					>
						Add this device to an existing wallet
					</button>
					{onClose ? (
						<button type="button" onClick={onClose}>
							Close
						</button>
					) : null}
				</div>
			</>
		);
	}

	// ── The set ──────────────────────────────────────────────────────────────────────
	return (
		<>
			<div className="card">
				<h2>Wallet</h2>
				{state.walletAddress ? (
					<>
						<div className="kv">
							<span className="k">Address</span>
							<span className="v" data-testid="settings-address">
								{state.walletAddress}
							</span>
						</div>
						{state.chains.map((row) => (
							<div
								className="kv"
								key={row.chainId}
								data-testid={`settings-chain-${row.chainId}`}
							>
								<span className="k">
									{row.chainName} ({row.chainId})
								</span>
								<span className="v">
									{row.deployed === null
										? "unreachable"
										: row.deployed
											? `deployed · ${row.owners} owner(s)`
											: "deploys with your first transaction"}
								</span>
							</div>
						))}
					</>
				) : (
					<p>{state.view === "loading" ? "Loading…" : "No data yet."}</p>
				)}
				{state.error ? (
					<div className="error" data-testid="manage-error">
						{state.error}
					</div>
				) : null}
			</div>

			{state.divergent ? (
				<div className="card" data-testid="manage-divergence">
					<h2>⚠ Owner sets differ between networks</h2>
					<p>
						The credentials that control this wallet are not the same on every
						network it is served on. This needs reconciliation — a change may
						not have reached every network yet. The list below is the set on{" "}
						{state.referenceChainName}.
					</p>
				</div>
			) : null}

			{state.view === "unreadable" ? (
				// WM-05: the set could not be read anywhere — say so; never render an empty list.
				<div className="card" data-testid="manage-unreadable">
					<h2>The owner set could not be read</h2>
					<p>
						None of the served networks could be reached, so what controls this
						wallet cannot be shown right now. This is a connectivity problem,
						not your credential list.
					</p>
					<div className="actions">
						<button type="button" onClick={() => void actions.load()}>
							Try again
						</button>
					</div>
				</div>
			) : null}

			{state.walletAddress && state.view === "set" && (
				<div className="card">
					<h2>Who can use this wallet</h2>
					{/* WM-06: the list is the one read from this network. */}
					{state.chains.length > 1 && state.referenceChainName ? (
						<p className="owner-meta">Read from {state.referenceChainName}.</p>
					) : null}
					{state.owners.map((row) => (
						<OwnerRowView
							key={row.ownerBytes}
							row={row}
							actions={actions}
							canRemove={state.owners.length > 1}
							onRemove={() => actions.startRemove(row)}
						/>
					))}
					{state.owners.length === 1 ? (
						<p data-testid="manage-last-owner-note">
							This is the only credential that can act on the wallet, so it
							cannot be removed — removing it would lock the wallet forever. Add
							another passkey or account first.
						</p>
					) : null}
					{state.strays.map((stray) => (
						<div
							className="kv"
							key={stray.credentialId ?? stray.ownerBytes}
							data-testid="manage-stray-credential"
						>
							<span className="k">
								{stray.name ??
									`${(stray.credentialId ?? stray.fingerprint).slice(0, 12)}…`}
							</span>
							<span className="v">
								{stray.removedAt
									? "removed — no longer an owner"
									: "NOT an owner of this wallet"}
							</span>
						</div>
					))}
					{!state.deployed ? (
						<p>
							The wallet is not deployed on any served network yet — owner
							management becomes available with its first transaction.
						</p>
					) : null}
				</div>
			)}

			{state.walletAddress && (
				<div className="card">
					<h2>Add a credential</h2>
					<div
						className="actions"
						style={{ flexDirection: "column", paddingTop: 4 }}
					>
						<button
							type="button"
							className="primary"
							onClick={() => {
								setAddVariant("this-device");
								actions.startAddThisDevice();
							}}
							data-testid="manage-add-passkey"
							disabled={!state.deployed}
						>
							Add a passkey on this device
						</button>
						<button
							type="button"
							onClick={() => {
								setAddVariant("second-device");
								actions.startAddSecondDevice();
							}}
							data-testid="manage-add-device"
							disabled={!state.deployed}
						>
							Add a passkey on another device
						</button>
						<button
							type="button"
							onClick={() => actions.startAddAddress()}
							data-testid="manage-add-address"
							disabled={!state.deployed}
						>
							Add an Ethereum account
						</button>
					</div>
				</div>
			)}

			<div className="card">
				<h2>Signed-in devices</h2>
				<p className="note">
					Lost a device, or signed in somewhere you no longer trust? Sign out
					everywhere ends the session on every device signed in to this wallet,
					this one included. Each one needs its passkey to sign in again.
				</p>
			</div>

			<div className="actions">
				{onClose ? (
					<button type="button" onClick={onClose} data-testid="manage-close">
						Done
					</button>
				) : (
					<button
						type="button"
						className="danger"
						onClick={() => void actions.logout()}
						disabled={state.busy}
					>
						Log out (revoke session)
					</button>
				)}
				<button
					type="button"
					className="danger"
					onClick={() => void actions.logoutAll()}
					disabled={state.busy}
					data-testid="manage-logout-all"
				>
					Sign out everywhere
				</button>
			</div>
		</>
	);
}

/** Why the user is looking at sign-in (G5), in words. */
const NOTICES: Record<ManagementNotice, string> = {
	"session-ended": "Your session ended. Sign in again.",
	"signed-out-everywhere": "You're signed out on every device.",
	"signed-out-everywhere-unconfirmed":
		"You're signed out on this device, but the wallet service couldn't confirm the others. They may still be signed in. Sign in and try again once you're back online.",
};

function OwnerRowView({
	row,
	actions,
	canRemove,
	onRemove,
}: {
	row: OwnerRow;
	actions: ManagementController;
	canRemove: boolean;
	onRemove: () => void;
}) {
	const [renaming, setRenaming] = useState(false);
	const [name, setName] = useState(row.name ?? "");
	const [saving, setSaving] = useState(false);

	useEffect(() => setName(row.name ?? ""), [row.name]);

	const saveName = async () => {
		if (!row.credentialId) return;
		setSaving(true);
		try {
			await actions.rename(row.credentialId, name.trim() || null);
			setRenaming(false);
		} finally {
			setSaving(false);
		}
	};

	// WM-03/WM-09: identifiable without a name — the device it was added on, where it is stored,
	// when it was added, and a fingerprint derived from its key.
	const device = addedFromLabel(row);
	const title =
		row.name ??
		(row.kind === "address"
			? "Ethereum account"
			: (device ?? (row.credentialId ? "Passkey" : "Passkey added elsewhere")));
	const storage = row.kind === "passkey" ? storageLabel(row) : null;
	const added = row.createdAt
		? `added ${new Date(row.createdAt).toLocaleDateString(undefined, {
				day: "numeric",
				month: "short",
				year: "numeric",
			})}`
		: null;

	return (
		<div
			className="owner-row"
			data-testid="manage-owner-row"
			data-fingerprint={row.fingerprint}
		>
			<div className="owner-head">
				<span className="owner-name" data-testid="manage-owner-name">
					{title}
				</span>
				{row.isCurrent ? (
					<span className="owner-badge" data-testid="manage-owner-current">
						Current
					</span>
				) : null}
			</div>
			<div className="owner-meta" data-testid="manage-owner-meta">
				{row.kind === "address" ? (
					<span style={{ fontFamily: "ui-monospace, monospace" }}>
						{row.address}
					</span>
				) : row.credentialId ? (
					<>
						{/* A user-given name hides the device from the title, so it moves here. */}
						{row.name && device && row.name !== device ? `${device} · ` : null}
						{storage ? (
							<span data-testid="manage-owner-storage">{storage}</span>
						) : null}
						{storage && added ? " · " : null}
						{added}
					</>
				) : (
					// WM-04: an owner with no registry row is listed, never silently omitted.
					"Added outside this app"
				)}
			</div>
			{renaming && row.credentialId ? (
				<div className="owner-foot">
					<input
						value={name}
						onChange={(event) => setName(event.target.value)}
						placeholder={device ?? "Name this passkey"}
						style={{
							flex: 1,
							borderRadius: 8,
							border: "1px solid var(--border)",
							padding: "6px 8px",
							background: "var(--bg)",
							color: "var(--fg)",
						}}
						data-testid="manage-rename-input"
					/>
					<button
						type="button"
						className="link"
						onClick={() => void saveName()}
						disabled={saving}
						data-testid="manage-rename-save"
					>
						Save
					</button>
				</div>
			) : (
				<div className="owner-foot">
					<span className="owner-fp" data-testid="manage-owner-fingerprint">
						{row.fingerprint}
					</span>
					<span className="owner-actions">
						{row.credentialId ? (
							<button
								type="button"
								className="link"
								onClick={() => setRenaming(true)}
								data-testid="manage-rename"
							>
								Rename
							</button>
						) : null}
						<button
							type="button"
							className="link danger"
							onClick={onRemove}
							disabled={!canRemove}
							title={
								canRemove
									? undefined
									: "The last remaining credential cannot be removed"
							}
							data-testid="manage-remove"
						>
							Remove
						</button>
					</span>
				</div>
			)}
		</div>
	);
}

/** Transports that mean a separate, roaming authenticator, such as a USB or NFC security key. */
const ROAMING_TRANSPORTS = new Set(["usb", "nfc", "ble"]);

/**
 * Where a passkey is stored, in a few words (PS-1): "Apple Passwords · synced", "Security key · this
 * device only", "This device only". The provider when its authenticator named one, a security key when
 * it is a roaming single-device key, and whether it is synced. Null for a row with no registry entry.
 * Display only: never an input to any decision.
 */
function storageLabel(row: OwnerRow): string | null {
	if (!row.storage) return null;
	const { provider, synced, deviceType } = row.storage;
	if (provider === null && synced === null && deviceType === null) {
		return "Where it is stored was not recorded";
	}
	const securityKey =
		provider === null &&
		deviceType === "singleDevice" &&
		!!row.transports?.some((transport) => ROAMING_TRANSPORTS.has(transport));
	const where = provider ?? (securityKey ? "Security key" : null);
	const sync = synced
		? "synced"
		: deviceType === "singleDevice"
			? "this device only"
			: deviceType === "multiDevice"
				? "not synced"
				: null;
	const label = [where, sync]
		.filter((part): part is string => part !== null)
		.join(" · ");
	return label.charAt(0).toUpperCase() + label.slice(1);
}
