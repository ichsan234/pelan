import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const source=await readFile('dist/server/index.js','utf8');
const worker=(await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'))).default;
class Bucket{records=new Map();seq=0;async get(key){const o=this.records.get(key);return o?{etag:o.etag,json:async()=>JSON.parse(o.body)}:null;}async put(key,body,options={}){let o=this.records.get(key),c=options.onlyIf;if(c instanceof Headers&&c.get('If-None-Match')==='*'&&o)return null;if(c?.etagMatches&&o?.etag!==c.etagMatches)return null;let etag='v'+(++this.seq);this.records.set(key,{body,etag});return{etag};}async delete(k){this.records.delete(k);}}
const bucket=new Bucket(),env={BUCKET:bucket,AUTH_PASSWORD_PEPPER:'isolated-test-pepper-not-a-production-secret'};
let ip=0;const req=(path,{body,method=body?'POST':'GET',cookie='',origin='https://pelan.test',headers={}}={})=>new Request('https://pelan.test'+path,{method,headers:{Origin:origin,'Content-Type':'application/json','CF-Connecting-IP':'test-'+(++ip),...(cookie?{Cookie:cookie}:{}),...headers},...(body?{body:JSON.stringify(body)}:{})});
const send=(path,opts)=>worker.fetch(req(path,opts),env);
const signup=(email='one@example.test')=>({email,password:'AnExamplePassword!123',name:'Pengasuh Uji',consent:true});
const cookieOf=r=>r.headers.get('set-cookie')?.split(';')[0];
let r=await send('/api/auth/signup',{body:signup()});assert.equal(r.status,201);let first=await r.json(),cookie=cookieOf(r);assert.match(r.headers.get('set-cookie'),/HttpOnly; Secure; SameSite=Lax/);assert.equal(first.recoveryCode.length,48);assert.equal(first.user.authType,'email');
assert.ok(!JSON.stringify([...bucket.records.values()]).includes(signup().password),'plaintext password must not be stored');
assert.equal((await send('/api/auth/signup',{body:signup()})).status,409);
assert.equal((await send('/api/auth/signup',{body:{...signup('weak@example.test'),password:'short'}})).status,400);
assert.equal((await send('/api/auth/signup',{body:{...signup('noconsent@example.test'),consent:false}})).status,400);
let profile={parent:'Ibu Uji',child:'Anak Uji',birth:'2024-01-01',city:'Bogor',province:'Jawa Barat',concern:'Dukungan gerak',movement:'Dengan bantuan',goals:'Bermain',consentedAt:new Date().toISOString()};
r=await send('/api/family',{cookie});assert.equal((await r.json()).user.email,'one@example.test');
assert.equal((await send('/api/family',{method:'PUT',cookie,body:{profile,notes:[{id:'1',text:'Catatan privat'}]}})).status,200);
assert.equal((await (await send('/api/family',{cookie})).json()).data.notes[0].text,'Catatan privat');
let second=await send('/api/auth/signup',{body:signup('two@example.test')}),cookie2=cookieOf(second);assert.equal(second.status,201);assert.deepEqual((await (await send('/api/family',{cookie:cookie2})).json()).data,{});
assert.equal((await send('/api/family',{method:'PUT',body:{notes:[]}})).status,401);
assert.equal((await send('/api/family',{method:'PUT',cookie,origin:'https://evil.test',body:{notes:[]}})).status,403);
assert.equal((await send('/api/auth/login',{body:{email:'one@example.test',password:'WrongPassword!123'}})).status,401);
assert.equal((await send('/api/auth/login',{body:signup(),origin:'https://evil.test'})).status,403);
assert.equal((await send('/api/auth/login',{body:signup()})).status,200);
assert.equal((await send('/api/auth/logout',{cookie,body:{}})).status,200);assert.equal((await (await send('/api/family',{cookie})).json()).user,null);
r=await send('/api/auth/login',{body:signup()});const oldCookie=cookieOf(r);assert.equal(r.status,200);
r=await send('/api/auth/recover',{body:{email:'one@example.test',password:'NewExamplePassword!123',recoveryCode:first.recoveryCode}});assert.equal(r.status,200);const updated=await r.json();assert.notEqual(updated.recoveryCode,first.recoveryCode);const resetCookie=cookieOf(r);
assert.equal((await (await send('/api/family',{cookie:oldCookie})).json()).user,null,'reset must revoke existing sessions');
assert.equal((await send('/api/auth/recover',{body:{email:'one@example.test',password:'NewExamplePassword!123',recoveryCode:first.recoveryCode}})).status,401);
assert.equal((await send('/api/auth/login',{body:signup()})).status,401);assert.equal((await send('/api/auth/login',{body:{email:'one@example.test',password:'NewExamplePassword!123'}})).status,200);
assert.equal((await (await send('/api/family',{cookie:resetCookie})).json()).data.notes[0].text,'Catatan privat');
assert.equal((await (await send('/auth/accounts/anything.json')).status),404);
// Concurrent duplicate registration must allow only one account creation.
let concurrent=await Promise.all([send('/api/auth/signup',{body:signup('race@example.test')}),send('/api/auth/signup',{body:signup('race@example.test')})]);assert.deepEqual(concurrent.map(x=>x.status).sort(),[201,409]);
// Block brute force attempts without trusting process-local counters.
for(let i=0;i<12;i++)await send('/api/auth/login',{body:{email:'limit@example.test',password:'WrongPassword!123'}});
assert.equal((await send('/api/auth/login',{body:{email:'limit@example.test',password:'WrongPassword!123'}})).status,429);
// Preserve preexisting ChatGPT identities and do not merge on email.
let legacy=await send('/api/family',{headers:{'oai-authenticated-user-id':'old-id','oai-authenticated-user-email':'one@example.test'}});assert.equal((await legacy.json()).user.authType,'chatgpt');
assert.equal((await worker.fetch(req('/api/auth/signup',{body:signup('storage@example.test')}),{})).status,503);
console.log('PASS internal accounts: signup, salts/hash-only storage, cookie session, reload, family isolation, login failures, logout, recovery rotation and session revocation, CSRF, atomic duplicate signup, persisted rate limits, legacy access, storage failure.');
let del=await send('/api/auth/delete-account',{cookie:cookie2,body:{email:'two@example.test',password:signup().password}});assert.equal(del.status,200);assert.equal((await (await send('/api/family',{cookie:cookie2})).json()).user,null);let recreate=await send('/api/auth/signup',{body:signup('two@example.test')});assert.equal(recreate.status,201);assert.equal((await (await send('/api/family',{cookie:cookie2})).json()).user,null);console.log('PASS: account deletion and old-session denial after re-registration.');
