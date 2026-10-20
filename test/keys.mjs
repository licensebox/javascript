// Synthetic hybrid Ed25519 + ML-DSA-65 keys for tests, from a 64-byte seed.
import {createPrivateKey,createPublicKey,sign} from 'node:crypto';

export function hybrid(seed) {
  const ed=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed.subarray(0,32)]),format:'der',type:'pkcs8'});
  const ml=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031204228020','hex'),seed.subarray(32)]),format:'der',type:'pkcs8'});
  const spki=key=>createPublicKey(key).export({format:'der',type:'spki'});
  return {
    installKey:'ed25519-mldsa65:'+seed.toString('base64url'),
    public:'ed25519-mldsa65:'+Buffer.concat([spki(ed).subarray(-32),spki(ml).subarray(-1952)]).toString('base64url'),
    sign:message=>Buffer.concat([sign(null,message,ed),sign(null,message,ml)]),
  };
}

export const TEST_KEY=hybrid(Buffer.alloc(64,1)).public;
