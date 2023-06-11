"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.keySign = exports.keyGen = void 0;
const world = 'world';
const libsignal_client_1 = require("@signalapp/libsignal-client");
const fs_1 = require("fs");
const path_1 = require("path");
// ✅ write to file ASYNCHRONOUSLY
function asyncWriteFile(filename, data) {
    return __awaiter(this, void 0, void 0, function* () {
        /**
         * flags:
         *  - w = Open file for reading and writing. File is created if not exists
         *  - a+ = Open file for reading and appending. The file is created if not exists
         */
        try {
            yield fs_1.promises.writeFile((0, path_1.join)(__dirname, filename), data, {
                flag: 'w',
            });
            const contents = yield fs_1.promises.readFile((0, path_1.join)(__dirname, filename), 'utf-8');
            console.log(contents); // 👉️ "One Two Three Four"
            return contents;
        }
        catch (err) {
            console.log(err);
            return 'Something went wrong';
        }
    });
}
function keyGen() {
    const privKey = libsignal_client_1.PrivateKey.generate();
    const pubKey = privKey.getPublicKey();
    const privB64 = privKey.serialize().toString('base64');
    const pubB64 = pubKey.serialize().toString('base64');
    return {
        pubKey: pubKey,
        privKey: privKey
    };
}
exports.keyGen = keyGen;
function keySign(privateKey, PrePubKey) {
    //const privKey: PrivateKey = PrivateKey.generate();
    //const pubKey : PublicKey = privKey.getPublicKey();
    //const signature = privateKey.sign(PrePubKey.getPublicKeyBytes())
    const signature = privateKey.sign(PrePubKey.serialize());
    const signatureB64 = signature.toString('base64');
    return signatureB64;
}
exports.keySign = keySign;
if (typeof require !== 'undefined' && require.main === module) {
    if (process.argv.length < 2) {
        console.error("That's sus :sadge:");
    }
    const count = parseInt(process.argv[2], 10);
    let keys = [];
    for (let i = 0; i < count; i++) {
        keys.push(keyGen());
    }
    let LongTermKey = keyGen();
    let PreKey = keyGen();
    let PreKeyBundle = {
        keyPair: PreKey,
        signature: keySign(LongTermKey.privKey, PreKey.pubKey)
    };
    var data = {
        identityKey: {
            publicKey: LongTermKey.pubKey.serialize().toString('base64'),
            privateKey: LongTermKey.privKey.serialize().toString('base64')
        },
        preKeys: keys.map(k => ({
            "pubKey": k.pubKey.serialize().toString('base64'),
            "privKey": k.privKey.serialize().toString('base64'),
        })),
        signedPreKey: {
            keyID: 1,
            publicKey: PreKeyBundle.keyPair.pubKey.serialize().toString('base64'),
            privateKey: PreKeyBundle.keyPair.privKey.serialize().toString('base64'),
            signature: PreKeyBundle.signature
        }
    };
    asyncWriteFile(`./${count}-keys.json`, JSON.stringify(data));
}
