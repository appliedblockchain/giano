import { describe, expect, it } from "vitest";
import { describeUserAgent } from "../src/services/user-agent.js";

const UA = {
	iphoneSafari:
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	iphoneChrome:
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
	macSafari:
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	macChrome:
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	windowsEdge:
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	androidChrome:
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	androidSamsung:
		"Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
	linuxFirefox:
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	headlessChrome:
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
};

describe("describeUserAgent", () => {
	it.each([
		["iphoneSafari", "iPhone", "Safari"],
		["iphoneChrome", "iPhone", "Chrome"],
		["macSafari", "Mac", "Safari"],
		["macChrome", "Mac", "Chrome"],
		["windowsEdge", "Windows", "Edge"],
		["androidChrome", "Android", "Chrome"],
		["androidSamsung", "Android", "Samsung Internet"],
		["linuxFirefox", "Linux", "Firefox"],
		["headlessChrome", "Linux", "Chrome"],
	] as const)("%s → %s · %s", (name, device, browser) => {
		expect(describeUserAgent(UA[name])).toEqual({ device, browser });
	});

	it("says nothing it does not know", () => {
		expect(describeUserAgent(undefined)).toEqual({
			device: null,
			browser: null,
		});
		expect(describeUserAgent("curl/8.7.1")).toEqual({
			device: null,
			browser: null,
		});
	});
});
