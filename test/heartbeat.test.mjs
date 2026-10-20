import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,existsSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {hybrid,TEST_KEY} from './keys.mjs';
import {Client,LicenseboxError} from '../dist/index.js';

function result(seconds = 0.2, online = true) {
  return {lease:{expires:new Date(Date.now()+seconds*1000).toISOString(),heartbeat:{interval_seconds:30,grace_seconds:90}},online};
}
function fixture(t) {
  const directory=mkdtempSync(join(tmpdir(),'licensebox-monitor-'));
  t.after(()=>rmSync(directory,{recursive:true,force:true}));
  return new Client({product:'demo',keys:{test:TEST_KEY},directory});
}
async function bounded(promise) {return Promise.race([promise,delay(800).then(()=>{throw new Error('watchdog failed to stop');})]);}

test('construction and missing heartbeat do not activate or create identity',async t=>{
  const client=fixture(t);
  await assert.rejects(client.heartbeat('core'),error=>error.code==='not_signed_in');
  assert.equal(existsSync(join(client.directory,'install.key')),false);
});
test('independent watchdog stops a hung renewal and ignores late success',async t=>{
  const client=fixture(t); let calls=0,release;
  client.heartbeat=async()=>++calls===1?result():new Promise(resolve=>{release=()=>resolve(result(60));});
  const monitor=await client.watch('core',{intervalSeconds:0.01});
  t.after(()=>{monitor.stop();release?.();});
  const failure=await bounded(monitor.done);
  assert.equal(failure.code,'expired'); assert.equal(monitor.signal.aborted,true); assert.equal(calls,2);
  release(); await delay(20); assert.equal((await monitor.done).code,'expired');
});
test('offline success cannot extend last signed deadline',async t=>{
  const client=fixture(t), initial=result(); let calls=0;
  client.heartbeat=async()=>++calls===1?initial:{...initial,online:false};
  const monitor=await client.watch('core',{intervalSeconds:0.01});
  const snapshot=monitor.latest;snapshot.lease.expires='2099-01-01T00:00:00Z';
  assert.equal((await bounded(monitor.done)).code,'expired'); assert.ok(calls>1);
});
test('refusal cancels work; rejected notification is contained',async t=>{
  const client=fixture(t);let calls=0,notified=false;
  client.heartbeat=async()=>{if(++calls===1)return result(60);throw new LicenseboxError('module_denied');};
  const monitor=await client.watch('core',{intervalSeconds:0.01,onStop:async()=>{notified=true;throw new Error('consumer');}});
  assert.equal((await bounded(monitor.done)).code,'module_denied');
  await delay(10);assert.equal(notified,true);assert.equal(monitor.signal.aborted,true);
});
test('consumer abort cancels inflight check and removes scheduling',async t=>{
  const client=fixture(t), consumer=new AbortController(); let calls=0,cancelled=false,entered;
  const started=new Promise(resolve=>{entered=resolve;});
  client.heartbeat=async(_module,{signal}={})=>{
    if(++calls===1)return result(60);
    entered();
    return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>{cancelled=true;reject(new LicenseboxError('cancelled'));},{once:true}));
  };
  const monitor=await client.watch('core',{intervalSeconds:0.01,signal:consumer.signal});
  await started;consumer.abort();assert.equal((await bounded(monitor.done)).code,'cancelled');
  assert.equal(cancelled,true);await delay(30);assert.equal(calls,2);monitor.stop();
});
test('explicit stop is idempotent and no slower-than-policy/invalid intervals',async t=>{
  const client=fixture(t);let calls=0;client.heartbeat=async()=>{calls++;return result(60);};
  for(const intervalSeconds of [0,-1,NaN,Infinity])await assert.rejects(client.watch('core',{intervalSeconds}),TypeError);
  const monitor=await client.watch('core',{intervalSeconds:1000});monitor.stop();monitor.stop();
  assert.equal(await monitor.done,undefined);await delay(30);assert.equal(calls,1);
});

test('returned heartbeat cannot mutate cached grants or expiry',async t=>{
  const client=fixture(t), key=hybrid(Buffer.from(Array.from({length:64},(_,i)=>i)));
  const now=Date.now()/1000,binding='m1:linux-dmi:'+'1'.repeat(64);
  const lease={v:3,kid:'test',product:'demo',machine:key.public,binding,modules:['core'],issued:new Date(now*1000).toISOString(),expires:new Date((now+60)*1000).toISOString()};
  const payload=Buffer.from(JSON.stringify(lease)),token=payload.toString('base64url')+'.'+key.sign(Buffer.concat([Buffer.from('licensebox lease v3\ned25519-mldsa65\n'),payload])).toString('base64url');
  client.keys={test:key.public};client.config.machineBinding=()=>binding;
  writeFileSync(join(client.directory,'install.key'),key.installKey);writeFileSync(join(client.directory,'lease'),token);
  client.post=async()=>({lease:token});
  const response=await client.heartbeat('core');response.lease.modules.push('export');response.lease.expires='2099-01-01T00:00:00Z';
  await assert.rejects(client.require('export'),error=>error.code==='module_denied');
  assert.equal((await client.lease()).expires,lease.expires);
  writeFileSync(join(client.directory,'install.key'),'damaged');
  await assert.rejects(client.heartbeat('core'),error=>error.code==='io_error');
  assert.equal(readFileSync(join(client.directory,'install.key'),'utf8'),'damaged');
});

test('offline monitor preserves absolute monotonic deadline across clock rollback',async t=>{
  const client=fixture(t),initial=result();let calls=0;
  client.heartbeat=async()=>++calls===1?initial:{...initial,online:false};
  const monitor=await client.watch('core',{intervalSeconds:0.01});
  const before=monitor.deadline;client.clock=()=>Date.now()/1000-3600;
  t.after(()=>monitor.stop());
  assert.equal((await bounded(monitor.done)).code,'expired');
  assert.equal(monitor.deadline,before);assert.ok(calls>1);
});
test('late online microtask cannot replace a deadline before pending expiry timer runs',async t=>{
  const client=fixture(t),initial=result(0.1);let calls=0,release,entered;
  const started=new Promise(resolve=>{entered=resolve;});
  client.heartbeat=async()=>{
    if(++calls===1)return initial;
    entered();return new Promise(resolve=>{release=()=>resolve(result(60));});
  };
  const monitor=await client.watch('core',{intervalSeconds:0.01});
  t.after(()=>{monitor.stop();release?.();});
  await started;
  // Delay timers while making the renewed result's microtask ready first.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,150);
  release();
  assert.equal((await bounded(monitor.done)).code,'expired');
  assert.equal(monitor.latest.lease.expires,initial.lease.expires);
});
test('known403 headers remain an explicit HTTP error when body exceeds budget',async t=>{
  const client=fixture(t),original=globalThis.fetch;
  globalThis.fetch=async(_url,{signal})=>new Response(new ReadableStream({
    start(controller){signal.addEventListener('abort',()=>controller.error(signal.reason),{once:true});}
  }),{status:403});
  try {
    await bounded(assert.rejects(client.post('/v1/renew',{},20),error=>error.code==='http_error'&&error.status===403));
  } finally {globalThis.fetch=original;}
});
