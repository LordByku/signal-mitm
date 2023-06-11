"use strict";
//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProtocolAddress = void 0;
const Native = require("../Native");
class ProtocolAddress {
    constructor(handle) {
        this._nativeHandle = handle;
    }
    static _fromNativeHandle(handle) {
        return new ProtocolAddress(handle);
    }
    static new(name, deviceId) {
        return new ProtocolAddress(Native.ProtocolAddress_New(name, deviceId));
    }
    name() {
        return Native.ProtocolAddress_Name(this);
    }
    deviceId() {
        return Native.ProtocolAddress_DeviceId(this);
    }
}
exports.ProtocolAddress = ProtocolAddress;
//# sourceMappingURL=Address.js.map