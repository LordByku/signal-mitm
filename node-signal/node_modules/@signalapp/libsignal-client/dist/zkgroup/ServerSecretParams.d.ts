/// <reference types="node" />
import ByteArray from './internal/ByteArray';
import ServerPublicParams from './ServerPublicParams';
import NotarySignature from './NotarySignature';
export default class ServerSecretParams extends ByteArray {
    private readonly __type?;
    static generate(): ServerSecretParams;
    static generateWithRandom(random: Buffer): ServerSecretParams;
    constructor(contents: Buffer);
    getPublicParams(): ServerPublicParams;
    sign(message: Buffer): NotarySignature;
    signWithRandom(random: Buffer, message: Buffer): NotarySignature;
}
