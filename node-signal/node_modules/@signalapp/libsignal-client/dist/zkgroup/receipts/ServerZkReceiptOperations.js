"use strict";
//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Native = require("../../../Native");
const Constants_1 = require("../internal/Constants");
const BigIntUtil_1 = require("../internal/BigIntUtil");
const ReceiptCredentialResponse_1 = require("./ReceiptCredentialResponse");
class ServerZkReceiptOperations {
    constructor(serverSecretParams) {
        this.serverSecretParams = serverSecretParams;
    }
    issueReceiptCredential(receiptCredentialRequest, receiptExpirationTime, receiptLevel) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.issueReceiptCredentialWithRandom(random, receiptCredentialRequest, receiptExpirationTime, receiptLevel);
    }
    issueReceiptCredentialWithRandom(random, receiptCredentialRequest, receiptExpirationTime, receiptLevel) {
        return new ReceiptCredentialResponse_1.default(Native.ServerSecretParams_IssueReceiptCredentialDeterministic(this.serverSecretParams.getContents(), random, receiptCredentialRequest.getContents(), receiptExpirationTime, (0, BigIntUtil_1.bufferFromBigUInt64BE)(receiptLevel)));
    }
    verifyReceiptCredentialPresentation(receiptCredentialPresentation) {
        Native.ServerSecretParams_VerifyReceiptCredentialPresentation(this.serverSecretParams.getContents(), receiptCredentialPresentation.getContents());
    }
}
exports.default = ServerZkReceiptOperations;
//# sourceMappingURL=ServerZkReceiptOperations.js.map