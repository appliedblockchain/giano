/**
 * The device and browser a request came from, from its User-Agent, in a few words ("iPhone",
 * "Safari"), so the wallet can say which device a passkey was added on (PS-1).
 *
 * Deliberately small: the device family and the browser, not versions or models (browsers reduce
 * their User-Agent to roughly that anyway). The User-Agent is whatever the browser sends, so this is
 * display only and never an input to any decision. Unknown values yield null.
 */
export type AddedFrom = { device: string | null; browser: string | null };

const DEVICES: readonly [RegExp, string][] = [
	[/iPhone/, "iPhone"],
	[/iPad/, "iPad"],
	[/Android/, "Android"],
	[/CrOS/, "ChromeOS"],
	[/Windows/, "Windows"],
	[/Macintosh|Mac OS X/, "Mac"],
	[/Linux/, "Linux"],
];

// Order matters: Chromium-based browsers also say "Chrome", and every iOS and Chromium browser
// also says "Safari".
const BROWSERS: readonly [RegExp, string][] = [
	[/EdgiOS|EdgA|Edg\//, "Edge"],
	[/OPR\/|Opera/, "Opera"],
	[/SamsungBrowser/, "Samsung Internet"],
	[/FxiOS|Firefox\//, "Firefox"],
	[/CriOS|Chrome\/|Chromium\//, "Chrome"],
	[/Version\/[\d.]+.*Safari\//, "Safari"],
];

export function describeUserAgent(userAgent: string | undefined): AddedFrom {
	if (!userAgent) return { device: null, browser: null };
	const pick = (table: readonly [RegExp, string][]) =>
		table.find(([pattern]) => pattern.test(userAgent))?.[1] ?? null;
	return { device: pick(DEVICES), browser: pick(BROWSERS) };
}

/** The two credential columns for a request's User-Agent. */
export function addedFromColumns(userAgent: string | undefined): {
	addedDevice: string | null;
	addedBrowser: string | null;
} {
	const { device, browser } = describeUserAgent(userAgent);
	return { addedDevice: device, addedBrowser: browser };
}
