import { useWalletKit } from "@appliedblockchain/giano-wallet-kit/react";

/**
 * Shown next to passkey prompts that carry the prefer-mobile hint. Enrollment of a new
 * credential is unhinted (design D3), so its screens do not render this.
 */
export function PasskeyDeviceGuidance() {
	const { config } = useWalletKit();
	if (config.passkeyDevicePreference !== "prefer-mobile") return null;
	return (
		<p data-testid="passkey-device-guidance">
			Your browser may offer a phone or QR code. You can also choose another
			available passkey.
		</p>
	);
}
