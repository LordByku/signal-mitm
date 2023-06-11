"use strict";
//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const Constants_1 = require("../internal/Constants");
const Native = require("../../../Native");
const UuidCiphertext_1 = require("./UuidCiphertext");
const ProfileKeyCiphertext_1 = require("./ProfileKeyCiphertext");
const ProfileKey_1 = require("../profiles/ProfileKey");
const UUIDUtil_1 = require("../internal/UUIDUtil");
class ClientZkGroupCipher {
    constructor(groupSecretParams) {
        this.groupSecretParams = groupSecretParams;
    }
    encryptUuid(uuid) {
        return new UuidCiphertext_1.default(Native.GroupSecretParams_EncryptUuid(this.groupSecretParams.getContents(), (0, UUIDUtil_1.fromUUID)(uuid)));
    }
    decryptUuid(uuidCiphertext) {
        return (0, UUIDUtil_1.toUUID)(Native.GroupSecretParams_DecryptUuid(this.groupSecretParams.getContents(), uuidCiphertext.getContents()));
    }
    encryptProfileKey(profileKey, uuid) {
        return new ProfileKeyCiphertext_1.default(Native.GroupSecretParams_EncryptProfileKey(this.groupSecretParams.getContents(), profileKey.getContents(), (0, UUIDUtil_1.fromUUID)(uuid)));
    }
    decryptProfileKey(profileKeyCiphertext, uuid) {
        return new ProfileKey_1.default(Native.GroupSecretParams_DecryptProfileKey(this.groupSecretParams.getContents(), profileKeyCiphertext.getContents(), (0, UUIDUtil_1.fromUUID)(uuid)));
    }
    encryptBlob(plaintext) {
        const random = (0, crypto_1.randomBytes)(Constants_1.RANDOM_LENGTH);
        return this.encryptBlobWithRandom(random, plaintext);
    }
    encryptBlobWithRandom(random, plaintext) {
        return Native.GroupSecretParams_EncryptBlobWithPaddingDeterministic(this.groupSecretParams.getContents(), random, plaintext, 0);
    }
    decryptBlob(blobCiphertext) {
        return Native.GroupSecretParams_DecryptBlobWithPadding(this.groupSecretParams.getContents(), blobCiphertext);
    }
}
exports.default = ClientZkGroupCipher;
//# sourceMappingURL=ClientZkGroupCipher.js.map