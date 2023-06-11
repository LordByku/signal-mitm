/// <reference types="node" />
export default class ByteArray {
    contents: Buffer;
    constructor(contents: Buffer, checkValid: (contents: Buffer) => void);
    protected static checkLength(expectedLength: number): (contents: Buffer) => void;
    getContents(): Buffer;
    serialize(): Buffer;
}
