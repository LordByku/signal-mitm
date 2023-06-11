const world = 'world';
import {
    HKDF,
    PrivateKey,
    PublicKey,
    SenderCertificate,
  } from '@signalapp/libsignal-client'
import { promises as fsPromises } from 'fs';
import { join } from 'path';

// ✅ write to file ASYNCHRONOUSLY
async function asyncWriteFile(filename: string, data: any) {
    /**
     * flags:
     *  - w = Open file for reading and writing. File is created if not exists
     *  - a+ = Open file for reading and appending. The file is created if not exists
     */
    try {
      await fsPromises.writeFile(join(__dirname, filename), data, {
        flag: 'w',
      });
  
      const contents = await fsPromises.readFile(
        join(__dirname, filename),
        'utf-8',
      );
      console.log(contents); // 👉️ "One Two Three Four"
  
      return contents;
    } catch (err) {
      console.log(err);
      return 'Something went wrong';
    }
  }
  

interface KeyPair {
    pubKey : PublicKey
    privKey : PrivateKey
}

interface PreKeyBundle{
  keyPair : KeyPair
  signature : string
}

export function keyGen() : KeyPair {
    const privKey: PrivateKey = PrivateKey.generate();
    const pubKey : PublicKey = privKey.getPublicKey();

    const privB64 = privKey.serialize().toString('base64');
    const pubB64 = pubKey.serialize().toString('base64');
    return {
        pubKey: pubKey,
        privKey: privKey
    } 
}

export function keySign(privateKey: PrivateKey, PrePubKey: PublicKey) : string {
  //const privKey: PrivateKey = PrivateKey.generate();
  //const pubKey : PublicKey = privKey.getPublicKey();

  //const signature = privateKey.sign(PrePubKey.getPublicKeyBytes())
  const signature = privateKey.sign(PrePubKey.serialize())


  const signatureB64 = signature.toString('base64');

  return signatureB64
}


if (typeof require !== 'undefined' && require.main === module) {
    if (process.argv.length < 2) {
        console.error("That's sus :sadge:");
    }

    const count = parseInt(process.argv[2], 10);
    let keys :Array<KeyPair> = [];

    for(let i=0; i<count; i++){
        keys.push(keyGen())
    }
    
    let LongTermKey: KeyPair = keyGen()
    
    let PreKey: KeyPair = keyGen()

    let PreKeyBundle : PreKeyBundle = {
      keyPair : PreKey,
      signature : keySign(LongTermKey.privKey, PreKey.pubKey)
    }

    var data = {
      identityKey : {
        publicKey: LongTermKey.pubKey.serialize().toString('base64'),
        privateKey: LongTermKey.privKey.serialize().toString('base64')
      },
      preKeys: keys.map(k => ({
        "pubKey": k.pubKey.serialize().toString('base64'),
        "privKey": k.privKey.serialize().toString('base64'),
        })),
      signedPreKey: {
        keyID: 1,
        publicKey : PreKeyBundle.keyPair.pubKey.serialize().toString('base64'),
        privateKey : PreKeyBundle.keyPair.privKey.serialize().toString('base64'),
        signature : PreKeyBundle.signature
      }

  };
    asyncWriteFile(`./${count}-keys.json`, JSON.stringify(data))
}