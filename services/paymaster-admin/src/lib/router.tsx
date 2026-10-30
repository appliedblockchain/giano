import { chakra, type HTMLChakraProps } from "@chakra-ui/react";
import { type MouseEvent, useSyncExternalStore } from "react";

/**
 * The console's routes: one per tab, and one per tenant (openspec redesign-paymaster-console, D1).
 *
 * Paths rather than a hash, because the container already serves `index.html` for any path it does
 * not know; `/api`, `/rpc`, `/assets` and `/config.json` are not route names, so nothing collides.
 * Not react-router: eight flat routes and one parameter are not worth a dependency that has to be
 * pinned, release-aged and reviewed (ABIP-6, ABIP-7).
 *
 * The deployment is deliberately not in the URL. A shared link opens on the reader's own selected
 * deployment; one that carried it would switch someone onto another chain by clicking it — the
 * accident `config.ts` exists to prevent.
 */
export type Tab =
	| "overview"
	| "tenants"
	| "paymaster"
	| "roles"
	| "timelock"
	| "activity"
	| "health"
	| "admins";

export type Route =
	| { tab: Tab; tenant?: undefined }
	| { tab: "tenants"; tenant: string }
	| { tab: "not-found"; tenant?: undefined };

export const TAB_PATHS: Record<Tab, string> = {
	overview: "/",
	tenants: "/tenants",
	paymaster: "/paymaster",
	roles: "/roles",
	timelock: "/timelock",
	activity: "/activity",
	health: "/health",
	admins: "/admins",
};

export function tenantPath(tenant: string): string {
	return `/tenants/${encodeURIComponent(tenant)}`;
}

export function parseRoute(pathname: string): Route {
	const path = pathname.replace(/\/+$/, "") || "/";
	const tenant = /^\/tenants\/([^/]+)$/.exec(path);
	if (tenant) return { tab: "tenants", tenant: decodeURIComponent(tenant[1]) };
	for (const [tab, tabPath] of Object.entries(TAB_PATHS))
		if (tabPath === path) return { tab: tab as Tab };
	return { tab: "not-found" };
}

/** `pushState` fires no event of its own; this one lets every `useRoute` hear a {@link navigate}. */
const NAVIGATE = "giano:navigate";

function subscribe(onChange: () => void): () => void {
	window.addEventListener("popstate", onChange);
	window.addEventListener(NAVIGATE, onChange);
	return () => {
		window.removeEventListener("popstate", onChange);
		window.removeEventListener(NAVIGATE, onChange);
	};
}

const currentPath = () => window.location.pathname;

export function useRoute(): Route {
	return parseRoute(useSyncExternalStore(subscribe, currentPath));
}

export function navigate(path: string): void {
	if (path === window.location.pathname) return;
	window.history.pushState(null, "", path);
	window.dispatchEvent(new Event(NAVIGATE));
	window.scrollTo(0, 0);
}

/**
 * A real `<a href>`, so open-in-new-tab, copy link and middle-click all behave as they do anywhere
 * else; a plain left click navigates in place.
 */
export function Link({
	to,
	onClick,
	...props
}: HTMLChakraProps<"a"> & { to: string }) {
	const follow = (event: MouseEvent<HTMLAnchorElement>) => {
		onClick?.(event);
		if (
			event.defaultPrevented ||
			event.button !== 0 ||
			event.metaKey ||
			event.ctrlKey ||
			event.shiftKey ||
			event.altKey
		)
			return;
		event.preventDefault();
		navigate(to);
	};
	return <chakra.a href={to} onClick={follow} {...props} />;
}
