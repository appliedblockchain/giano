import { useCallback, useEffect, useState } from "react";

/**
 * Light or dark, as the `.dark` / `.light` class on `<html>` that Chakra's `_dark` conditions read.
 *
 * `public/color-mode.js` sets the class before the first paint; this hook takes it from there. A
 * choice made with the toggle is remembered; until there is one, the console follows the browser,
 * including when the system switches mode under an open page. Not `next-themes`, which
 * custom-example uses: for one class and one key it is a dependency to pin and review for nothing.
 */
export type ColorMode = "light" | "dark";

const STORAGE_KEY = "giano:paymaster-admin:color-mode";

function current(): ColorMode {
	return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

function apply(mode: ColorMode): void {
	const root = document.documentElement;
	root.classList.remove(mode === "dark" ? "light" : "dark");
	root.classList.add(mode);
	root.style.colorScheme = mode;
}

function remembered(): ColorMode | undefined {
	try {
		const value = localStorage.getItem(STORAGE_KEY);
		return value === "light" || value === "dark" ? value : undefined;
	} catch {
		return undefined;
	}
}

export function useColorMode(): {
	colorMode: ColorMode;
	toggleColorMode: () => void;
} {
	const [colorMode, setColorMode] = useState<ColorMode>(current);

	useEffect(() => {
		if (remembered()) return;
		const query = matchMedia("(prefers-color-scheme: dark)");
		const follow = () => {
			if (remembered()) return;
			const next = query.matches ? "dark" : "light";
			apply(next);
			setColorMode(next);
		};
		query.addEventListener("change", follow);
		return () => query.removeEventListener("change", follow);
	}, []);

	const toggleColorMode = useCallback(() => {
		const next = current() === "dark" ? "light" : "dark";
		apply(next);
		setColorMode(next);
		try {
			localStorage.setItem(STORAGE_KEY, next);
		} catch {
			// Not remembering is fine; the page is already in the chosen mode.
		}
	}, []);

	return { colorMode, toggleColorMode };
}
