import { createSystem, defaultConfig, defineConfig } from "@chakra-ui/react";

/**
 * custom-example's theme, so the console and the sample dApp read as one product: the system font
 * stack, the indigo `brand` and emerald `accent` palettes, and Chakra's default `gray`, which is
 * the zinc scale the design uses for every neutral.
 *
 * PLACEHOLDER VALUES, as they are in custom-example: `brand` and `accent` stand in for the Applied
 * Edge Design System tokens. Swap the values below when those land and nothing else changes —
 * components only ever say `colorPalette="brand"`, `"accent"` or `"timelock"`.
 *
 * `timelock` is the console's own: every control and marker for something that waits out the
 * timelock's delay is purple with a clock, so an operator can tell at a glance which actions take
 * effect now and which are only proposed. Its own scale, not Chakra's `purple`, whose 700 is a
 * different, darker hue from the one in the design.
 */
const config = defineConfig({
	globalCss: {
		"html, body, #root": { minHeight: "100vh" },
		body: {
			background: "canvas",
			color: "fg",
			fontFamily: "body",
		},
	},
	theme: {
		tokens: {
			fonts: {
				heading: { value: 'system-ui, -apple-system, "Segoe UI", sans-serif' },
				body: { value: 'system-ui, -apple-system, "Segoe UI", sans-serif' },
				mono: {
					value: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
				},
			},
			colors: {
				brand: {
					50: { value: "#eef2ff" },
					100: { value: "#e0e7ff" },
					200: { value: "#c7d2fe" },
					300: { value: "#a5b4fc" },
					400: { value: "#818cf8" },
					500: { value: "#6366f1" },
					600: { value: "#4338ca" },
					700: { value: "#3730a3" },
					800: { value: "#312e81" },
					900: { value: "#1e1b4b" },
					950: { value: "#130f38" },
				},
				accent: {
					50: { value: "#ecfdf5" },
					100: { value: "#d1fae5" },
					200: { value: "#a7f3d0" },
					300: { value: "#6ee7b7" },
					400: { value: "#34d399" },
					500: { value: "#10b981" },
					600: { value: "#059669" },
					700: { value: "#047857" },
					800: { value: "#065f46" },
					900: { value: "#064e3b" },
					950: { value: "#022c22" },
				},
				timelock: {
					50: { value: "#faf5ff" },
					100: { value: "#f3e8ff" },
					200: { value: "#e9d5ff" },
					300: { value: "#d8b4fe" },
					400: { value: "#c084fc" },
					500: { value: "#a855f7" },
					600: { value: "#9333ea" },
					700: { value: "#7e22ce" },
					800: { value: "#6b21a8" },
					900: { value: "#581c87" },
					950: { value: "#3b0764" },
				},
			},
		},
		semanticTokens: {
			colors: {
				/** The page ground. White, with `bg.subtle` for the header band and table heads. */
				canvas: {
					value: { _light: "white", _dark: "{colors.gray.950}" },
				},
				/** Cards and panels: the same as the ground, told apart by their border. */
				surface: {
					value: { _light: "white", _dark: "{colors.gray.900}" },
				},
				brand: palette("brand"),
				accent: palette("accent"),
				timelock: palette("timelock"),
			},
		},
	},
});

/**
 * The semantic tokens Chakra's `colorPalette` reads, for one of the scales above, in both modes.
 * The same mapping custom-example spells out by hand for `brand` and `accent`.
 */
function palette(name: "brand" | "accent" | "timelock") {
	const scale = (light: number, dark: number) => ({
		value: {
			_light: `{colors.${name}.${light}}`,
			_dark: `{colors.${name}.${dark}}`,
		},
	});
	return {
		solid: scale(name === "timelock" ? 700 : 600, 400),
		contrast: {
			value: { _light: "white", _dark: `{colors.${name}.950}` },
		},
		fg: scale(700, 300),
		muted: scale(100, 900),
		subtle: scale(50, 950),
		emphasized: scale(700, 300),
		focusRing: scale(600, 400),
	};
}

export const system = createSystem(defaultConfig, config);
