import * as Native from '../Native';
export declare class ProtocolAddress {
    readonly _nativeHandle: Native.ProtocolAddress;
    private constructor();
    static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress;
    static new(name: string, deviceId: number): ProtocolAddress;
    name(): string;
    deviceId(): number;
}
