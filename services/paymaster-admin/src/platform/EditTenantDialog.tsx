import {
	Alert,
	Button,
	Checkbox,
	Dialog,
	Field,
	Input,
	Portal,
	Stack,
	Text,
	Textarea,
} from "@chakra-ui/react";
import { useEffect, useRef, useState } from "react";
import type { PlatformTenant } from "../lib/platform-api";
import {
	formToPolicy,
	type PolicyForm,
	policyProblems,
	policyToForm,
} from "../lib/policy";
import { PolicyFields } from "../tenants/PolicyFields";
import { OriginsField } from "./CreateTenantDialog";
import { usePlatformAction } from "./LifecycleDialogs";
import {
	ApiErrorAlert,
	issuesByField,
	linesToList,
	parseJsonObject,
} from "./shared";

type Form = {
	rpName: string;
	expectedOrigins: string;
	allowedDappOrigins: string;
	corsOrigins: string;
	openRegistration: boolean;
	policy: PolicyForm;
	branding: string;
};

const toForm = (tenant: PlatformTenant): Form => ({
	rpName: tenant.rpName,
	// the wallet origin is always an expected origin, so it is not offered for removal here
	expectedOrigins: tenant.expectedOrigins
		.filter((origin) => origin !== tenant.walletOrigin)
		.join("\n"),
	allowedDappOrigins: tenant.allowedDappOrigins.join("\n"),
	corsOrigins: tenant.corsOrigins.join("\n"),
	openRegistration: tenant.openRegistration,
	policy: policyToForm(tenant.policy),
	branding: JSON.stringify(tenant.branding, null, 2),
});

/**
 * Edit a tenant's mutable fields (specs/PLATFORM-ADMIN-SPECS.md §11.3). Optimistic: the request
 * carries the version the form was opened at, and a 412 means someone changed the tenant since.
 * The tenant page then reloads underneath while this form keeps what the platform admin typed, so it can be
 * re-applied against the new version rather than lost.
 */
export function EditTenantDialog({
	open,
	onClose,
	tenant,
	onSaved,
	onConflict,
}: {
	open: boolean;
	onClose: () => void;
	tenant: PlatformTenant;
	onSaved: () => void;
	onConflict: () => void;
}) {
	const { act, busy, error, reset } = usePlatformAction();
	const [form, setForm] = useState<Form>(() => toForm(tenant));
	const [baseVersion, setBaseVersion] = useState(tenant.version);
	const [conflicted, setConflicted] = useState(false);
	const issues = issuesByField(error);
	const branding = parseJsonObject(form.branding);

	// A fresh open starts from the tenant as it is now. While open, the page re-reads the tenant on
	// every refresh and hands this a new object each time: that must not wipe what is being typed.
	// Only a new version replaces the form, and only while nothing has been typed into it; with edits
	// in it, the save meets the 412 and the edits are kept for re-applying.
	const opened = useRef<{ version: number; form: Form }>(undefined);
	useEffect(() => {
		if (!open) {
			opened.current = undefined;
			return;
		}
		if (conflicted) return;
		const previous = opened.current;
		const pristine =
			previous !== undefined &&
			JSON.stringify(form) === JSON.stringify(previous.form);
		if (
			previous === undefined ||
			(tenant.version !== previous.version && pristine)
		) {
			const fresh = toForm(tenant);
			opened.current = { version: tenant.version, form: fresh };
			setForm(fresh);
			setBaseVersion(tenant.version);
		}
	}, [open, tenant, conflicted, form]);

	const set =
		(
			field:
				| "rpName"
				| "expectedOrigins"
				| "allowedDappOrigins"
				| "corsOrigins"
				| "branding",
		) =>
		(event: { target: { value: string } }) =>
			setForm({ ...form, [field]: event.target.value });

	const close = () => {
		setConflicted(false);
		reset();
		onClose();
	};

	const save = async () => {
		if (!branding.ok) return;
		const result = await act((api) =>
			api.update(tenant.slug, baseVersion, {
				rpName: form.rpName.trim(),
				expectedOrigins: linesToList(form.expectedOrigins),
				allowedDappOrigins: linesToList(form.allowedDappOrigins),
				corsOrigins: linesToList(form.corsOrigins),
				openRegistration: form.openRegistration,
				policy: formToPolicy(form.policy),
				branding: branding.value,
			}),
		);
		if (!result) return;
		if (result.ok) {
			setConflicted(false);
			onSaved();
			close();
		} else if (result.error.status === 412) {
			setConflicted(true);
			if (typeof result.error.version === "number")
				setBaseVersion(result.error.version);
			onConflict();
		}
	};

	const fieldError = (name: string) => issues[name]?.join(" · ");

	return (
		<Dialog.Root
			open={open}
			onOpenChange={(event) => !event.open && close()}
			size="lg"
			scrollBehavior="inside"
		>
			<Portal>
				<Dialog.Backdrop />
				<Dialog.Positioner>
					<Dialog.Content>
						<Dialog.Header>
							<Dialog.Title>Edit {tenant.slug}</Dialog.Title>
						</Dialog.Header>
						<Dialog.Body>
							<Stack gap="4">
								{conflicted && (
									<Alert.Root status="warning" size="sm">
										<Alert.Indicator />
										<Alert.Content>
											<Alert.Title>
												Someone else changed this tenant
											</Alert.Title>
											<Alert.Description>
												The tenant page now shows its current values. Your edits
												are kept below — check them against what changed, then
												save again to apply them on top.
											</Alert.Description>
										</Alert.Content>
									</Alert.Root>
								)}
								<Text fontSize="sm" color="fg.muted">
									Slug, id, wallet origin ({tenant.walletOrigin}) and RP ID (
									{tenant.rpId}) cannot change: a tenant that needs a new origin
									is a new tenant.
								</Text>
								<Field.Root required invalid={!!fieldError("rpName")}>
									<Field.Label>Display name</Field.Label>
									<Input value={form.rpName} onChange={set("rpName")} />
									<Field.ErrorText>{fieldError("rpName")}</Field.ErrorText>
								</Field.Root>
								<OriginsField
									label="Expected origins"
									help="Extra ceremony origins; the wallet origin is always one."
									value={form.expectedOrigins}
									onChange={set("expectedOrigins")}
									error={fieldError("expectedOrigins")}
								/>
								<OriginsField
									label="dApp origins"
									help="The dApps allowed to open this wallet."
									value={form.allowedDappOrigins}
									onChange={set("allowedDappOrigins")}
									error={fieldError("allowedDappOrigins")}
								/>
								<OriginsField
									label="CORS origins"
									help="dApp origins that call wallet-api cross-origin."
									value={form.corsOrigins}
									onChange={set("corsOrigins")}
									error={fieldError("corsOrigins")}
								/>
								<Checkbox.Root
									checked={form.openRegistration}
									onCheckedChange={(event) =>
										setForm({
											...form,
											openRegistration: event.checked === true,
										})
									}
								>
									<Checkbox.HiddenInput />
									<Checkbox.Control />
									<Checkbox.Label>Open registration</Checkbox.Label>
								</Checkbox.Root>
								{fieldError("adminKeys") && (
									<Text color="red.fg" fontSize="sm">
										{fieldError("adminKeys")}
									</Text>
								)}
								<PolicyFields
									value={form.policy}
									onChange={(policy) => setForm({ ...form, policy })}
									error={fieldError("policy")}
								/>
								<Field.Root invalid={!branding.ok || !!fieldError("branding")}>
									<Field.Label>Branding (JSON)</Field.Label>
									<Textarea
										value={form.branding}
										onChange={set("branding")}
										rows={3}
										fontFamily="mono"
										fontSize="sm"
									/>
									<Field.ErrorText>
										{!branding.ok
											? "Not a JSON object"
											: fieldError("branding")}
									</Field.ErrorText>
									<Field.HelperText>
										Stored, but not yet read by any wallet UI — changing it
										changes nothing on screen (O-7).
									</Field.HelperText>
								</Field.Root>
								{error && !error.issues && error.status !== 412 && (
									<ApiErrorAlert error={error} />
								)}
							</Stack>
						</Dialog.Body>
						<Dialog.Footer>
							<Button variant="ghost" onClick={close} disabled={busy}>
								Cancel
							</Button>
							<Button
								colorPalette="brand"
								onClick={() => void save()}
								loading={busy}
								disabled={
									!branding.ok ||
									!form.rpName.trim() ||
									policyProblems(form.policy).length > 0
								}
							>
								Save
							</Button>
						</Dialog.Footer>
					</Dialog.Content>
				</Dialog.Positioner>
			</Portal>
		</Dialog.Root>
	);
}
