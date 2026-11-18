import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {fixture} from './fixture.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
test('Chromium private account window rejects web framing and runs UV/PRF through WASM/Noise', {timeout:120000},async()=>{
  const env=await fixture();const {popup,site}=env;
  try{
    await popup.locator('#pairing-code').fill(env.info.code);await popup.locator('#pair').click();
    await popup.locator('.match').first().waitFor();
    const extension=popup.url().split('/').slice(0,3).join('/');
    // A website cannot embed or fetch the private account confirmation page.
    const iframe=await site.evaluate(async extension=>{
      const frame=document.createElement('iframe');frame.src=extension+'/account-access.html';document.body.append(frame);
      await new Promise(resolve=>setTimeout(resolve,200));return frame.contentDocument?.title??null;
    },extension);
    assert.equal(iframe,null);
    const command=env.ready.replace(/\.json$/,'.account-command.json');
    const reply=env.ready.replace(/\.json$/,'.account-reply.json');
    await writeFile(command+'.tmp',JSON.stringify({phase:'register',require_prf:true}),{mode:0o600});await rename(command+'.tmp',command);
    await pause(100);await popup.reload();await popup.locator('#account-continue').waitFor();
    const opened=site.context().waitForEvent('page');await popup.locator('#account-continue').click();const account=await opened;
    await account.locator('#continue:not([disabled])').waitFor();
    assert.equal(await account.locator('#server').textContent(),'https://example.test');
    const cdp=await site.context().newCDPSession(account);await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,hasPrf:true,automaticPresenceSimulation:true}});
    // The public adapter uses real Chrome WebAuthn and proves deterministic PRF
    // for this virtual key. No PRF bytes are returned to the Node test process.
    const checked=await account.evaluate(async()=>{
      const {performAccountCeremony}=await import('./account-ceremony.js');
      const options={operation_id:crypto.randomUUID(),phase:'register',challenge:btoa('12345678901234567890123456789012').replaceAll('=',''),rp_id:'example.test',rp_name:'Test',user_id:'22222222-2222-4222-8222-222222222222',user_name:'test@example.test',credential_ids:[],prf_input:btoa('abcdefghijklmnopqrstuvwx12345678').replaceAll('=','')};
      const permission=await chrome.permissions.contains({origins:['https://example.test/*']});if(!permission)throw new Error('fixture host grant missing');
      const registered=await performAccountCeremony({options,require_prf:true},navigator.credentials);registered.prf.fill(0);
      options.phase='test';options.challenge=btoa('abcdefghijklmnopqrstuvwx12345678').replaceAll('=','');
      const first=await performAccountCeremony({options,require_prf:true},navigator.credentials);
      const second=await performAccountCeremony({options,require_prf:true},navigator.credentials);
      const result={first:first.prf.length,second:second.prf.length,equal:first.prf.every((v,i)=>v===second.prf[i]),origin:JSON.parse(atob(first.response.client_data_json.replaceAll('-','+').replaceAll('_','/'))).origin};
      first.prf.fill(0);second.prf.fill(0);return result;
    });
    assert.equal(checked.first,32);assert.equal(checked.second,32);assert.equal(checked.equal,true);assert.equal(checked.origin,extension);
    await account.locator('#continue').click();
    let output;for(let i=0;i<100;i++){try{output=JSON.parse(await readFile(reply,'utf8'));break;}catch(error){if(error.code!=='ENOENT')throw error;}await pause(50);}
    assert.equal(output?.response?.phase,'register');
    assert.ok(!JSON.stringify(output).includes('"prf":'),'native test receipt never stores PRF bytes');
    assert.equal(JSON.parse(Buffer.from(output.response.client_data_json,'base64url')).origin,extension);
  }finally{await env.close();}
});
