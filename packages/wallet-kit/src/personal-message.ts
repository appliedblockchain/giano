import { toPersonalMessageBytes } from "@appliedblockchain/giano-wallet-core";
import { bytesToHex } from "viem";

/** How a consent screen shows a personal_sign / eth_sign message. */
export type PersonalMessageDisplay = {
	/** The signed bytes as text, or as hex when they cannot be shown safely as text. */
	body: string;
	/** True when `body` is hex. The screen should warn that the user signs these exact bytes. */
	rawHex: boolean;
};

/** Invisible or reordering characters (Unicode category C and default-ignorables), except tab and line breaks. */
const HIDDEN_CHARACTER = /(?![\t\n\r])[\p{C}\p{Default_Ignorable_Code_Point}]/u;

/**
 * The bytes a personal_sign / eth_sign request signs, ready to show. Text only when the bytes
 * are valid UTF-8 with no hidden character; otherwise hex.
 */
export function describePersonalMessage(
	message: string,
): PersonalMessageDisplay {
	const bytes = toPersonalMessageBytes(message);
	try {
		// ignoreBOM keeps a leading BOM, so the check rejects it instead of hiding it.
		const text = new TextDecoder("utf-8", {
			fatal: true,
			ignoreBOM: true,
		}).decode(bytes);
		if (!HIDDEN_CHARACTER.test(text)) return { body: text, rawHex: false };
	} catch {
		// Not valid UTF-8.
	}
	return { body: bytesToHex(bytes), rawHex: true };
}
