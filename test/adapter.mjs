// Test-only synthetic host and clock overrides; no production credentials.
import {readFileSync} from 'node:fs';
import {Client, LicenseboxError, deriveBinding, nativeBinding, verifyLease} from '../dist/index.js';
const request = JSON.parse(readFileSync(0,'utf8'));
try {
  let value;
  if (request.op === 'derive') value = deriveBinding(request.product,request.source,request.raw_id);
  else if (request.op === 'verify') value = verifyLease(request.token,request.product,request.keys,request.now);
  else if (request.op === 'native') value = nativeBinding(request.product);
  else {
    const client = new Client({...request,caBundle:request.ca_bundle,machineBinding:Object.hasOwn(request,'binding')?()=>request.binding:undefined,clock:()=>request.now,onSignIn:()=>{},version:'conformance'});
    switch (request.op) {
      case 'lease': value = await client.lease(); break;
      case 'require': value = await client.require(request.module ?? 'core'); break;
      case 'repeat': value = [await client.require('core'),await client.require('core')]; break;
      case 'heartbeat': value = await client.heartbeat(request.module ?? 'core'); break;
      case 'heartbeat-repeat': await client.heartbeat(request.module ?? 'core'); value = await client.heartbeat(request.module ?? 'core'); break;
      case 'heartbeat-after-require': await client.require(request.module ?? 'core'); value = await client.heartbeat(request.module ?? 'core'); break;
      case 'status': value = await client.status(); break;
      case 'sign_in': value = await client.signIn(3); break;
      case 'logout': await client.logout(); value = null; break;
      case 'modules': value = await client.modules(); break;
      case 'request': value = await client.requestAccess(['export'],'café – test'); break;
      case 'requests': value = await client.requests(); break;
      case 'access-link': value = await client.accessLink(); break;
      case 'record': await client.record('export',true,0.125); await client.record('export',false,0.025); value = null; break;
      default: throw new Error('unknown operation');
    }
  }
  console.log(JSON.stringify({ok:true,value}));
} catch (error) {
  if (!(error instanceof LicenseboxError)) throw error;
  console.log(JSON.stringify({ok:false,error:error.code}));
}
