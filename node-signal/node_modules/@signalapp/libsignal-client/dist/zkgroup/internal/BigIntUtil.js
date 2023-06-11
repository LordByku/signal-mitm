"use strict";
//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
exports.bufferFromBigUInt64BE = void 0;
const UINT64_MAX = BigInt('0xFFFFFFFFFFFFFFFF');
function bufferFromBigUInt64BE(value) {
    if (value < 0 || value > UINT64_MAX) {
        throw new RangeError(`value ${value} isn't representable as a u64`);
    }
    const result = Buffer.alloc(8);
    result.writeBigUInt64BE(value);
    return result;
}
exports.bufferFromBigUInt64BE = bufferFromBigUInt64BE;
//# sourceMappingURL=BigIntUtil.js.map