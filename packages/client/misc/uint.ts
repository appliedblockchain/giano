
export const uint8ArrayToUint256 = (array: ArrayBuffer) => {
    const hex = Array.from(new Uint8Array(array))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    return BigInt('0x' + hex);
};

export const hexToUint8Array = (hex: string) => {
    if (hex.startsWith('0x')) {
        hex = hex.slice(2);
    }
    return new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
};
