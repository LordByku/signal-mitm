/// <reference types="node" />
export type UUIDType = string;
export declare function toUUID(array: Buffer): UUIDType;
export declare function fromUUID(uuid: UUIDType): Buffer;
