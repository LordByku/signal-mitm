/// <reference types="node" />
import ServerPublicParams from '../ServerPublicParams';
import AuthCredential from './AuthCredential';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialResponse from './AuthCredentialResponse';
import AuthCredentialWithPni from './AuthCredentialWithPni';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse';
import GroupSecretParams from '../groups/GroupSecretParams';
import { UUIDType } from '../internal/UUIDUtil';
export default class ClientZkAuthOperations {
    serverPublicParams: ServerPublicParams;
    constructor(serverPublicParams: ServerPublicParams);
    receiveAuthCredential(uuid: UUIDType, redemptionTime: number, authCredentialResponse: AuthCredentialResponse): AuthCredential;
    /**
     * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
     *
     * @param redemptionTime - This is provided by the server as an integer, and should be passed through directly.
     */
    receiveAuthCredentialWithPni(aci: UUIDType, pni: UUIDType, redemptionTime: number, authCredentialResponse: AuthCredentialWithPniResponse): AuthCredentialWithPni;
    createAuthCredentialPresentation(groupSecretParams: GroupSecretParams, authCredential: AuthCredential): AuthCredentialPresentation;
    createAuthCredentialPresentationWithRandom(random: Buffer, groupSecretParams: GroupSecretParams, authCredential: AuthCredential): AuthCredentialPresentation;
    createAuthCredentialWithPniPresentation(groupSecretParams: GroupSecretParams, authCredential: AuthCredentialWithPni): AuthCredentialPresentation;
    createAuthCredentialWithPniPresentationWithRandom(random: Buffer, groupSecretParams: GroupSecretParams, authCredential: AuthCredentialWithPni): AuthCredentialPresentation;
}
