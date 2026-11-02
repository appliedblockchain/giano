import { Button, Field, Group, Input, InputAddon } from "@chakra-ui/react";
import { type ReactNode, useCallback, useMemo, useState } from "react";
import { type Address, formatUnits, type Hex } from "viem";
import {
	type Parsed,
	parseAddress,
	parseAmount,
	parseCalldata,
	parseWholeNumber,
} from "../lib/validate";
import { useConsole } from "../shell/ConsoleContext";

/**
 * A field's text and what it parses to (openspec D7). The form reads `value`, which is set only
 * when the text is valid, so nothing downstream casts a string to an address or an amount.
 */
export type InputState<T> = {
	text: string;
	setText: (text: string) => void;
	value: T | undefined;
	error: string | undefined;
	/**
	 * Empties the field, once its write succeeds — unless it has been changed since the render this
	 * `clear` came from. A write's success arrives after the receipt and a refresh, and whatever the
	 * operator typed next in the meantime is theirs, not the old write's to wipe.
	 */
	clear: () => void;
};

export function useInput<T>(
	parse: (text: string) => Parsed<T>,
	initial = "",
): InputState<T> {
	const [text, setText] = useState(initial);
	const parsed = useMemo(() => parse(text), [parse, text]);
	const clear = useCallback(
		() => setText((current) => (current === text ? "" : current)),
		[text],
	);
	return { text, setText, value: parsed.value, error: parsed.error, clear };
}

export const useAddressInput = (): InputState<Address> =>
	useInput(parseAddress);

export const useCalldataInput = (): InputState<Hex> => useInput(parseCalldata);

/**
 * An amount in the selected chain's currency, at most `max` when given. `allowZero` for a fee, where
 * 0 means free; anything moved (funding, withdrawing, staking) must be more than 0.
 */
export function useAmountInput(
	max?: bigint,
	maxLabel?: string,
	{ allowZero = false }: { allowZero?: boolean } = {},
): InputState<bigint> {
	const { nativeCurrency } = useConsole().deployment;
	const parse = useCallback(
		(text: string) =>
			parseAmount(text, { currency: nativeCurrency, max, maxLabel, allowZero }),
		[nativeCurrency, max, maxLabel, allowZero],
	);
	return useInput(parse);
}

export function useWholeNumberInput(
	limits: { max?: bigint; unit?: string } = {},
	initial = "",
): InputState<bigint> {
	const { max, unit } = limits;
	const parse = useCallback(
		(text: string) => parseWholeNumber(text, { max, unit }),
		[max, unit],
	);
	return useInput(parse, initial);
}

type FieldProps<T> = {
	input: InputState<T>;
	label: string;
	helper?: ReactNode;
	placeholder?: string;
	disabled?: boolean;
};

/** A labelled input whose problem is stated under it, as it is typed. */
function TextField<T>({
	input,
	label,
	helper,
	placeholder,
	disabled,
	end,
	mono,
	inputMode,
}: FieldProps<T> & {
	end?: ReactNode;
	mono?: boolean;
	/** The keyboard a phone shows. */
	inputMode?: "decimal" | "numeric";
}) {
	return (
		<Field.Root invalid={input.error !== undefined} disabled={disabled}>
			<Field.Label fontSize="sm">{label}</Field.Label>
			<Group attached width="full">
				<Input
					size="sm"
					value={input.text}
					onChange={(event) => input.setText(event.target.value)}
					placeholder={placeholder}
					fontFamily={mono ? "mono" : undefined}
					inputMode={inputMode}
					spellCheck={false}
					autoComplete="off"
				/>
				{end}
			</Group>
			{input.error ? (
				<Field.ErrorText>{input.error}</Field.ErrorText>
			) : (
				helper && <Field.HelperText>{helper}</Field.HelperText>
			)}
		</Field.Root>
	);
}

export function AddressInput(props: FieldProps<Address>) {
	return <TextField placeholder="0x…" mono {...props} />;
}

/** An amount, labelled with the chain's currency, with a Max control when `max` is given. */
export function AmountInput({
	max,
	...props
}: FieldProps<bigint> & { max?: bigint }) {
	const { nativeCurrency } = useConsole().deployment;
	return (
		<TextField
			placeholder="0.0"
			mono
			inputMode="decimal"
			{...props}
			end={
				<>
					{max !== undefined && (
						<Button
							size="sm"
							variant="outline"
							disabled={props.disabled || max === 0n}
							onClick={() =>
								props.input.setText(formatUnits(max, nativeCurrency.decimals))
							}
						>
							Max
						</Button>
					)}
					<InputAddon>{nativeCurrency.symbol}</InputAddon>
				</>
			}
		/>
	);
}

export function WholeNumberInput({
	unit,
	...props
}: FieldProps<bigint> & { unit?: string }) {
	return (
		<TextField
			placeholder="0"
			mono
			inputMode="numeric"
			{...props}
			end={unit && <InputAddon>{unit}</InputAddon>}
		/>
	);
}

/** Raw calldata, `0x…`, for a call made after an upgrade. */
export function CalldataInput(props: FieldProps<Hex>) {
	return <TextField placeholder="0x (none)" mono {...props} />;
}
