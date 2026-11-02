import { describe, expect, it } from "vitest";
import { parseRoute, tenantPath } from "./router";

describe("parseRoute", () => {
	it("maps each tab's path to the tab", () => {
		expect(parseRoute("/")).toEqual({ tab: "overview" });
		expect(parseRoute("/tenants")).toEqual({ tab: "tenants" });
		expect(parseRoute("/timelock")).toEqual({ tab: "timelock" });
		expect(parseRoute("/admins")).toEqual({ tab: "admins" });
	});

	it("ignores a trailing slash", () => {
		expect(parseRoute("/roles/")).toEqual({ tab: "roles" });
		expect(parseRoute("//")).toEqual({ tab: "overview" });
	});

	it("reads a tenant from its path, decoded", () => {
		expect(parseRoute("/tenants/byo")).toEqual({
			tab: "tenants",
			tenant: "byo",
		});
		expect(parseRoute(tenantPath("a b"))).toEqual({
			tab: "tenants",
			tenant: "a b",
		});
	});

	it("says an unknown path is not found", () => {
		expect(parseRoute("/settings")).toEqual({ tab: "not-found" });
		expect(parseRoute("/tenants/byo/edit")).toEqual({ tab: "not-found" });
	});
});
