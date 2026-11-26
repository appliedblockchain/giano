import type {
	ChainProgress,
	ManagementChainStatus,
	PasskeyAddedFrom,
	SponsorshipRefusalReason,
} from "@appliedblockchain/giano-wallet-kit";
import type { ReactNode } from "react";
import { renderSVG } from "uqr";
import { refusalCopy } from "../sponsorship-copy";

/** The WM-48/WM-49 copy: who can act on the refusal, keyed off the machine-readable reason. */
export function RefusalNotice({
	reason,
	message,
}: {
	reason: SponsorshipRefusalReason;
	message: string;
}) {
	const copy = refusalCopy(reason);
	return (
		<div
			className="card"
			data-testid="manage-sponsorship-refusal"
			data-reason={reason}
		>
			<h2>{copy.title}</h2>
			<p>{copy.body}</p>
			<p>
				<b>{copy.action}</b>
			</p>
			<p style={{ fontSize: 12 }}>{message}</p>
		</div>
	);
}

/** Per-chain progress (WM-44): visible until every served chain has answered. */
export function ChainProgressList({ progress }: { progress: ChainProgress[] }) {
	const describe = (row: ChainProgress) => {
		switch (row.state) {
			case "waiting":
				return "waiting…";
			case "checking":
				return "checking…";
			case "skipped":
				return row.detail ?? "skipped";
			case "refused":
				return row.detail ?? "refused";
			case "submitted":
				return "submitted — waiting for confirmation…";
			case "confirmed":
				return "confirmed ✓";
			case "failed":
				return `failed: ${row.detail ?? "unknown error"}`;
		}
	};
	return (
		<div data-testid="manage-chain-progress">
			{progress.map((row) => (
				<div
					className="kv"
					key={row.chainId}
					data-testid={`manage-chain-progress-${row.chainId}`}
					data-state={row.state}
				>
					<span className="k">
						{row.chainName} ({row.chainId})
					</span>
					<span className="v">{describe(row)}</span>
				</div>
			))}
		</div>
	);
}

/** Names every served chain the change will be attempted on (WM-43). */
export function ChainsNotice({ chains }: { chains: ManagementChainStatus[] }) {
	const names = chains.map((chain) => `${chain.chainName} (${chain.chainId})`);
	return (
		<p data-testid="manage-chains-notice">
			This change applies on every network this wallet serves:{" "}
			<b>{names.join(", ")}</b>. A network where the wallet is not deployed yet
			is skipped and stated.
		</p>
	);
}

export function FlowShell({
	title,
	children,
}: {
	title: string;
	children: ReactNode;
}) {
	return (
		<div className="card">
			<h2>{title}</h2>
			{children}
		</div>
	);
}

export const inputStyle = {
	width: "100%",
	marginTop: 4,
	borderRadius: 8,
	border: "1px solid var(--border)",
	padding: "8px",
	background: "var(--bg)",
	color: "var(--fg)",
} as const;

/**
 * The device and browser a passkey was added from, as "iPhone · Safari" (PS-1). Null when nothing
 * was recorded. Self-reported by that browser: display only.
 */
export function addedFromLabel(row: {
	addedFrom: PasskeyAddedFrom | null;
}): string | null {
	const parts = [row.addedFrom?.device, row.addedFrom?.browser].filter(
		(part): part is string => !!part,
	);
	return parts.length > 0 ? parts.join(" · ") : null;
}

/**
 * The pairing link as a QR code (PS-2), for a phone to scan. Black on white with a quiet border,
 * whatever the theme, because camera apps read dark-on-light codes most reliably. The SVG is
 * generated here from the link, so it holds nothing but the code's own markup.
 */
/** The QR code's displayed size, in CSS pixels: large enough for a phone camera at arm's length. */
const QR_SIZE = 200;

export function PairingQr({ url }: { url: string }) {
	// uqr's SVG has a viewBox and no size; give it one, or a shrink-to-fit box may squeeze it.
	const svg = renderSVG(url, {
		ecc: "M",
		border: 2,
		pixelSize: 6,
		whiteColor: "#ffffff",
		blackColor: "#000000",
	}).replace("<svg ", `<svg width="${QR_SIZE}" height="${QR_SIZE}" `);
	return (
		<div
			style={{
				background: "#ffffff",
				borderRadius: 8,
				padding: 8,
				width: "fit-content",
				margin: "8px auto",
				lineHeight: 0,
			}}
			data-testid="manage-claim-qr"
			// biome-ignore lint/security/noDangerouslySetInnerHtml: uqr builds this SVG locally from the pairing link; no outside markup reaches it.
			dangerouslySetInnerHTML={{ __html: svg }}
		/>
	);
}
