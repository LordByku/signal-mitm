"use strict";
//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Native = require("../../../Native");
const Constants_1 = require("../internal/Constants");
const AuthCredential_1 = require("./AuthCredential");
const AuthCredentialPresentation_1 = require("./AuthCredentialPresentation");
const AuthCredentialWithPni_1 = require("./AuthCredentialWithPni");
const UUIDUtil_1 = require("../internal/UUIDUtil");
class ClientZkAuthOperations {
    constructor(serverPublicParams) {
        this.serverPublicParams = serverPublicParams;
    }
    receiveAuthCredential(uuid, redemptionTime, authCredentialResponse) {
        return new AuthCredential_1.default(Native.ServerPublicParams_ReceiveAuthCredential(this.serverPublicParams.getContents(), (0, UUIDUtil_1.fromUUID)(uuid), redemptionTime, authCredentialResponse.getContents()));
    }
    /**
     * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
     *
     * @param redemptionTime - This is provided by the server as an integer, and should be passed through directly.
     */
    receiveAuthCredentialWithPni(aci, pni, redemptionTime, authCredentialResponse) {
        return new AuthCredentialWithPni_1.default(Native.ServerPublicParams_ReceiveAuthCredentialWithPni(this.serverPublicParams.getContents(), (0, UUIDUtil_1.fromUUID)(aci), (0, UUIDUtil_1.fromUUID)(pni), redemptionTime, authCredentialResponse.getContents()));
    }
    createAuthCredentialPresentation(groupSecretParams, authCredential) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.createAuthCredentialPresentationWithRandom(random, groupSecretParams, authCredential);
    }
    createAuthCredentialPresentationWithRandom(random, groupSecretParams, authCredential) {
        return new AuthCredentialPresentation_1.default(Native.ServerPublicParams_CreateAuthCredentialPresentationDeterministic(this.serverPublicParams.getContents(), random, groupSecretParams.getContents(), authCredential.getContents()));
    }
    createAuthCredentialWithPniPresentation(groupSecretParams, authCredential) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.createAuthCredentialWithPniPresentationWithRandom(random, groupSecretParams, authCredential);
    }
    createAuthCredentialWithPniPresentationWithRandom(random, groupSecretParams, authCredential) {
        return new AuthCredentialPresentation_1.default(Native.ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(this.serverPublicParams.getContents(), random, groupSecretParams.getContents(), authCredential.getContents()));
    }
}
exports.default = ClientZkAuthOperations;
//# sourceMappingURL=ClientZkAuthOperations.js.map