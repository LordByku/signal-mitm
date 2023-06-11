"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const ByteArray_1 = require("./internal/ByteArray");
const Native = require("../../Native");
class ServerPublicParams extends ByteArray_1.default {
    constructor(contents) {
        super(contents, Native.ServerPublicParams_CheckValidContents);
    }
    verifySignature(message, notarySignature) {
        Native.ServerPublicParams_VerifySignature(this.contents, message, notarySignature.getContents());
    }
}
exports.default = ServerPublicParams;
//# sourceMappingURL=ServerPublicParams.js.map