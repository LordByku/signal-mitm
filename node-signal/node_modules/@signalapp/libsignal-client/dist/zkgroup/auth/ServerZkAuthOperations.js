"use strict";
//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Constants_1 = require("../internal/Constants");
const Native = require("../../../Native");
const AuthCredentialResponse_1 = require("./AuthCredentialResponse");
const AuthCredentialWithPniResponse_1 = require("./AuthCredentialWithPniResponse");
const UUIDUtil_1 = require("../internal/UUIDUtil");
class ServerZkAuthOperations {
    constructor(serverSecretParams) {
        this.serverSecretParams = serverSecretParams;
    }
    issueAuthCredential(uuid, redemptionTime) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.issueAuthCredentialWithRandom(random, uuid, redemptionTime);
    }
    issueAuthCredentialWithRandom(random, uuid, redemptionTime) {
        return new AuthCredentialResponse_1.default(Native.ServerSecretParams_IssueAuthCredentialDeterministic(this.serverSecretParams.getContents(), random, (0, UUIDUtil_1.fromUUID)(uuid), redemptionTime));
    }
    issueAuthCredentialWithPni(aci, pni, redemptionTime) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.issueAuthCredentialWithPniWithRandom(random, aci, pni, redemptionTime);
    }
    issueAuthCredentialWithPniWithRandom(random, aci, pni, redemptionTime) {
        return new AuthCredentialWithPniResponse_1.default(Native.ServerSecretParams_IssueAuthCredentialWithPniDeterministic(this.serverSecretParams.getContents(), random, (0, UUIDUtil_1.fromUUID)(aci), (0, UUIDUtil_1.fromUUID)(pni), redemptionTime));
    }
    verifyAuthCredentialPresentation(groupPublicParams, authCredentialPresentation, now = new Date()) {
        Native.ServerSecretParams_VerifyAuthCredentialPresentation(this.serverSecretParams.getContents(), groupPublicParams.getContents(), authCredentialPresentation.getContents(), Math.floor(now.getTime() / 1000));
    }
}
exports.default = ServerZkAuthOperations;
//# sourceMappingURL=ServerZkAuthOperations.js.map