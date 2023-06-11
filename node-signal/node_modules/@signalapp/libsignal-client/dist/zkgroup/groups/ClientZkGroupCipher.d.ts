/// <reference types="node" />
import UuidCiphertext from './UuidCiphertext';
import ProfileKeyCiphertext from './ProfileKeyCiphertext';
import ProfileKey from '../profiles/ProfileKey';
import GroupSecretParams from './GroupSecretParams';
import { UUIDType } from '../internal/UUIDUtil';
export default class ClientZkGroupCipher {
    groupSecretParams: GroupSecretParams;
    constructor(groupSecretParams: GroupSecretParams);
    encryptUuid(uuid: UUIDType): UuidCiphertext;
    decryptUuid(uuidCiphertext: UuidCiphertext): UUIDType;
    encryptProfileKey(profileKey: ProfileKey, uuid: UUIDType): ProfileKeyCiphertext;
    decryptProfileKey(profileKeyCiphertext: ProfileKeyCiphertext, uuid: UUIDType): ProfileKey;
    encryptBlob(plaintext: Buffer): Buffer;
    encryptBlobWithRandom(random: Buffer, plaintext: Buffer): Buffer;
    decryptBlob(blobCiphertext: Buffer): Buffer;
}
