"use strict";
//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Native = require("../../Native");
const ByteArray_1 = require("./internal/ByteArray");
const Constants_1 = require("./internal/Constants");
const ServerPublicParams_1 = require("./ServerPublicParams");
const NotarySignature_1 = require("./NotarySignature");
class ServerSecretParams extends ByteArray_1.default {
    static generate() {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return ServerSecretParams.generateWithRandom(random);
    }
    static generateWithRandom(random) {
        return new ServerSecretParams(Native.ServerSecretParams_GenerateDeterministic(random));
    }
    constructor(contents) {
        super(contents, Native.ServerSecretParams_CheckValidContents);
    }
    getPublicParams() {
        return new ServerPublicParams_1.default(Native.ServerSecretParams_GetPublicParams(this.contents));
    }
    sign(message) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.signWithRandom(random, message);
    }
    signWithRandom(random, message) {
        return new NotarySignature_1.default(Native.ServerSecretParams_SignDeterministic(this.contents, random, message));
    }
}
exports.default = ServerSecretParams;
//# sourceMappingURL=ServerSecretParams.js.map