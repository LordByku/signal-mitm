"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromUUID = exports.toUUID = void 0;
function toUUID(array) {
    const hex = array.toString('hex');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
exports.toUUID = toUUID;
function fromUUID(uuid) {
    let i = 0;
    const array = Buffer.alloc(16);
    uuid.replace(/[0-9A-F]{2}/gi, (oct) => {
        array[i++] = parseInt(oct, 16);
        return '';
    });
    return array;
}
exports.fromUUID = fromUUID;
//# sourceMappingURL=UUIDUtil.js.map