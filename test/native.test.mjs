import test from 'node:test';
import assert from 'node:assert/strict';
import {Client, deriveBinding, nativeBinding, LicenseboxError} from '../dist/index.js';

test('missing native identity refuses access before server contact',async()=>{
  const client=new Client({product:'demo',keys:{test:'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE'},
    server:'http://127.0.0.1:1',machineBinding:()=>''});
  await assert.rejects(client.require('core'),error=>error instanceof LicenseboxError&&error.code==='identity_unavailable');
});
test('invalid native sources fail closed',()=>{
  for(const value of ['', 'hostname','0'.repeat(32),'f'.repeat(32)])
    assert.throws(()=>deriveBinding('demo','linux-machine-id',value),LicenseboxError);
});
test('remote plaintext licensing endpoints are rejected',()=>{
  assert.throws(()=>new Client({product:'demo',keys:{test:'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE'},server:'http://example.invalid'}),TypeError);
});
test('native identity is stable and product-scoped',{skip:process.env.LICENSEBOX_TEST_NATIVE!=='1'},()=>{
  const first=nativeBinding('licensebox-test-a');
  assert.ok(first===nativeBinding('licensebox-test-a'),'native identity changed');
  assert.ok(first!==nativeBinding('licensebox-test-b'),'native identity is not product-scoped');
});
