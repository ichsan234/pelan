// Internal email accounts. Secrets and records live only in the hosted runtime/R2.
const SESSION_COOKIE='__Host-pelan_session';
const SESSION_AGE=7*24*60*60;
const utf8=new TextEncoder();
const hex=bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');
const randomHex=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',utf8.encode(s)));
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status});};
const secureEqual=(a,b)=>{if(typeof a!=='string'||typeof b!=='string')return false;let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0;};
const readJson=async(bucket,key)=>{const o=await bucket.get(key);return o?o.json():null;};
const writeJson=(bucket,key,value,options={})=>bucket.put(key,JSON.stringify(value),{httpMetadata:{contentType:'application/json'},...options});
function sessionToken(request){return (request.headers.get('Cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(SESSION_COOKIE+'='))?.slice(SESSION_COOKIE.length+1);}
function sessionCookie(token,age=SESSION_AGE){return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;}
async function passwordHash(password,salt,pepper){
 const material=await crypto.subtle.importKey('raw',utf8.encode(password),'PBKDF2',false,['deriveBits']);
 const derived=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',iterations:100000,salt:utf8.encode(salt)},material,256);
 const key=await crypto.subtle.importKey('raw',utf8.encode(pepper),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return hex(await crypto.subtle.sign('HMAC',key,derived));
}
async function accountIdentity(request,env){
 const token=sessionToken(request);
 if(token){
  if(!/^[a-f0-9]{64}$/.test(token)||!env.BUCKET)return null;
  const session=await readJson(env.BUCKET,'auth/sessions/'+await sha(token)+'.json');
  if(!session||session.expiresAt<=Date.now())return null;
  const account=await readJson(env.BUCKET,session.accountKey);
  if(!account||account.version!==session.version||account.id!==session.accountId)return null;
  return {id:'email:'+account.id,email:account.email,name:account.name,authType:'email',emailVerified:false};
 }
 const id=request.headers.get('oai-authenticated-user-id');
 return id?{id,email:request.headers.get('oai-authenticated-user-email')||'',authType:'chatgpt'}:null;
}
async function newSession(request,env,account,accountKey){
 const token=randomHex(32),key='auth/sessions/'+await sha(token)+'.json';
 await writeJson(env.BUCKET,key,{accountKey,accountId:account.id,version:account.version,expiresAt:Date.now()+SESSION_AGE*1000});
 const old=sessionToken(request);if(old&&/^[a-f0-9]{64}$/.test(old))await env.BUCKET.delete('auth/sessions/'+await sha(old)+'.json');
 return sessionCookie(token);
}
async function throttle(env,key,limit){
 const storageKey='auth/limits/'+await sha(key)+'.json',now=Date.now();
 for(let attempt=0;attempt<4;attempt++){
  const obj=await env.BUCKET.get(storageKey);let count=obj?await obj.json():null;
  if(!count||count.until<=now)count={count:0,until:now+15*60*1000};
  if(count.count>=limit)fail('Terlalu banyak percobaan. Coba kembali dalam 15 menit.',429);
  count.count++;
  let result;try{result=await writeJson(env.BUCKET,storageKey,count,{onlyIf:obj?{etagMatches:obj.etag}:new Headers({'If-None-Match':'*'})});}catch(e){if(String(e).includes('412'))continue;throw e;}
  if(result)return;
 }
 fail('Permintaan sedang diproses. Coba kembali sebentar lagi.',429);
}
async function authRequest(request,env){
 const url=new URL(request.url),action=url.pathname.slice('/api/auth/'.length);
 if(request.method!=='POST')return json({error:'Metode tidak didukung.'},405);
 if(request.headers.get('Origin')!==url.origin)return json({error:'Asal permintaan tidak diizinkan.'},403);
 if(!request.headers.get('Content-Type')?.startsWith('application/json'))return json({error:'Format tidak didukung.'},415);
 if(!env.BUCKET||!env.AUTH_PASSWORD_PEPPER)return json({error:'Layanan akun belum tersedia. Coba lagi nanti.'},503);
 try{
  if(action==='logout'){
   const token=sessionToken(request);if(token&&/^[a-f0-9]{64}$/.test(token))await env.BUCKET.delete('auth/sessions/'+await sha(token)+'.json');
   return new Response(JSON.stringify({ok:true}),{headers:{...headers,'Content-Type':'application/json','Set-Cookie':sessionCookie('',0)}});
  }
  if(!['signup','login','recover','delete-account'].includes(action))return json({error:'Tidak ditemukan.'},404);
  const text=await request.text();if(text.length>8192)fail('Formulir terlalu panjang.',413);
  let body;try{body=JSON.parse(text);}catch{fail('Format formulir tidak valid.');}
  if(!body||typeof body!=='object')fail('Formulir tidak valid.');
  const email=typeof body.email==='string'?body.email.trim().toLowerCase():'';
  if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))fail('Masukkan alamat email yang valid.');
  await throttle(env,'ip:'+(request.headers.get('CF-Connecting-IP')||'unknown'),40);
  await throttle(env,'email:'+email,12);
  const accountKey='auth/accounts/'+await sha(email)+'.json';
  const password=body.password;
  if(typeof password!=='string'||password.length<12||password.length>128)fail('Password harus berisi 12–128 karakter.');
  const existing=await env.BUCKET.get(accountKey),account=existing?await existing.json():null;
  if(action==='delete-account'){
   const identity=await accountIdentity(request,env);
   if(!identity||identity.authType!=='email'||identity.email!==email||!account)fail('Silakan masuk ke akun yang ingin dihapus.',401);
   const calculated=await passwordHash(password,account.salt,env.AUTH_PASSWORD_PEPPER);
   if(!secureEqual(calculated,account.passwordHash))fail('Password tidak sesuai.',401);
   await env.BUCKET.delete('families/'+await sha(identity.id)+'.json');
   await env.BUCKET.delete(accountKey);
   const token=sessionToken(request);if(token)await env.BUCKET.delete('auth/sessions/'+await sha(token)+'.json');
   return new Response(JSON.stringify({ok:true}),{headers:{...headers,'Content-Type':'application/json','Set-Cookie':sessionCookie('',0)}});
  }
  let result=account,recoveryCode=null;
  if(action==='signup'){
   if(!body.consent)fail('Setujui pembuatan akun untuk melanjutkan.');
   if(typeof body.name!=='string'||!body.name.trim()||body.name.trim().length>120)fail('Isi nama orang tua / pengasuh (maksimal 120 karakter).');
   if(account)fail('Pendaftaran tidak dapat dilakukan. Jika sudah pernah mendaftar, coba masuk atau gunakan kode pemulihan.',409);
   const salt=randomHex(16);recoveryCode=randomHex(24);
   result={id:crypto.randomUUID(),email,name:body.name.trim(),salt,passwordHash:await passwordHash(password,salt,env.AUTH_PASSWORD_PEPPER),algorithm:'PBKDF2-SHA256-100000+HMAC-SHA256',recoveryHash:await sha(recoveryCode),version:1,createdAt:new Date().toISOString(),emailVerified:false,consentedAt:new Date().toISOString()};
   let saved;try{saved=await writeJson(env.BUCKET,accountKey,result,{onlyIf:new Headers({'If-None-Match':'*'})});}catch(e){if(String(e).includes('412'))fail('Akun sudah terdaftar. Silakan masuk.',409);throw e;}
   if(!saved)fail('Akun sudah terdaftar. Silakan masuk.',409);
  }else if(action==='login'){
   const calculated=await passwordHash(password,account?.salt||'pelan-dummy-salt-for-login-check',env.AUTH_PASSWORD_PEPPER);
   if(!account||!secureEqual(calculated,account.passwordHash))fail('Email atau password tidak sesuai.',401);
  }else{
   const code=typeof body.recoveryCode==='string'?body.recoveryCode.trim().toLowerCase().replace(/[\s-]/g,''):'';
   if(!account||!secureEqual(await sha(code),account.recoveryHash))fail('Email atau kode pemulihan tidak sesuai.',401);
   const salt=randomHex(16);recoveryCode=randomHex(24);
   result={...account,salt,passwordHash:await passwordHash(password,salt,env.AUTH_PASSWORD_PEPPER),recoveryHash:await sha(recoveryCode),version:account.version+1};
   const saved=await writeJson(env.BUCKET,accountKey,result,{onlyIf:{etagMatches:existing.etag}});
   if(!saved)fail('Akun berubah saat diproses. Silakan coba kembali.',409);
  }
  const cookie=await newSession(request,env,result,accountKey);
  return new Response(JSON.stringify({ok:true,user:{email:result.email,name:result.name,authType:'email',emailVerified:false},...(recoveryCode?{recoveryCode}:{})}),{status:action==='signup'?201:200,headers:{...headers,'Content-Type':'application/json','Set-Cookie':cookie}});
 }catch(error){return json({error:error.status?error.message:'Layanan akun mengalami gangguan. Jika pendaftaran tadi terputus, coba masuk dengan email dan password yang sama.'},error.status||503);}
}

