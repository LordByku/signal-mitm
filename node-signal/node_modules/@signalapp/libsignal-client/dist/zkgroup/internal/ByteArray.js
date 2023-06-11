"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const Errors_1 = require("../../Errors");
class ByteArray {
    constructor(contents, checkValid) {
        checkValid(contents);
        this.contents = Buffer.from(contents);
    }
    static checkLength(expectedLength) {
        return (contents) => {
            if (contents.length !== expectedLength) {
                throw new Errors_1.LibSignalErrorBase(`Length of array supplied was ${contents.length} expected ${expectedLength}`, undefined, this.name);
            }
        };
    }
    getContents() {
        return this.contents;
    }
    serialize() {
        return Buffer.from(this.contents);
    }
}
exports.default = ByteArray;
//# sourceMappingURL=ByteArray.js.map