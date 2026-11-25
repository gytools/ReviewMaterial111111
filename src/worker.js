import { reportTemplate } from './report-template.js';
import { page } from './screens.js';
const COOKIE='__Host-review_session';
const encoder=new TextEncoder();
const now=()=>Math.floor(Date.now()/1000);
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const unhex=s=>Uint8Array.from(s.match(/../g)||[],x=>parseInt(x,16));
const random=(n=32)=>hex(crypto.getRandomValues(new Uint8Array(n)));
const digest=async text=>hex(await crypto.subtle.digest('SHA-256',encoder.encode(text)));
function fail(status,message){throw Object.assign(new Error(message),{status});}
function safeJSON(data){return JSON.stringify(data).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');}
const publicUser=u=>({id:u.id,username:u.username,display_name:u.display_name,role:u.role,student_id:u.student_id,active:!!u.active,must_change:!!u.must_change});
function response(data,status=200,extra={}){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8',...extra}});}
function html(text){return new Response(text,{headers:{'Content-Type':'text/html; charset=utf-8'}});}
function redirect(path){return new Response(null,{status:303,headers:{Location:path}});}
const cookie=(token,maxAge)=>`${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
async function body(request){if(!request.headers.get('content-type')?.startsWith('application/json'))fail(415,'请使用网页提交。');const text=await request.text();if(text.length>20000)fail(413,'提交内容过长。');try{return JSON.parse(text);}catch{fail(400,'提交内容格式错误。');}}
async function passwordHash(password,salt,secret){
 const pepper=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const prehash=await crypto.subtle.sign('HMAC',pepper,encoder.encode(password));
 const key=await crypto.subtle.importKey('raw',prehash,'PBKDF2',false,['deriveBits']);
 return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:unhex(salt),iterations:100000,hash:'SHA-256'},key,256));
}
function equal(a,b){if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0;}
function validPassword(v){if(typeof v!=='string'||v.length<12||v.length>128)fail(400,'密码需为 12—128 个字符。');return v;}
function username(v){if(typeof v!=='string'||! /^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$/.test(v))fail(400,'账号需为 3—32 位字母、数字、点、下划线或短横线。');return v.toLowerCase();}
function displayName(v){if(typeof v!=='string'||!v.trim()||v.length>50)fail(400,'请填写 1—50 字的显示名称。');return v.trim();}
async function rateLimit(env,scope,key,max){
 const window=Math.floor(now()/900);const id=await digest(scope+':'+window+':'+key);
 const row=await env.DB.prepare('INSERT INTO rate_limits(key,hits,expires_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET hits=hits+1 RETURNING hits').bind(id,now()+1800).first();
 if(row.hits>max)fail(429,'尝试次数较多，请 15 分钟后重试。');
}
async function currentUser(request,env){
 const token=(request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1);
 if(!token||! /^[a-f0-9]{64}$/.test(token))return null;
 return env.DB.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1').bind(await digest(token),now()).first();
}
async function issueSession(env,user){const token=random();await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await digest(token),user.id,now()+43200).run();return cookie(token,43200);}
async function verifyPassword(env,u,password){const actual=await passwordHash(password,u?.salt||'0'.repeat(32),env.APP_SECRET);return !!u&&equal(actual,u.password_hash);}
async function api(request,env,url){
 const path=url.pathname;
 if(request.method!=='GET'&&request.method!=='HEAD'){
  if(request.headers.get('origin')!==url.origin)fail(403,'请求来源不正确，请从本站操作。');
 }
 if(path==='/api/setup'&&request.method==='POST'){
  await rateLimit(env,'setup',request.headers.get('cf-connecting-ip')||'unknown',5);
  const b=await body(request);
  if(!env.SETUP_TOKEN||typeof b.setup_token!=='string'||!equal(await digest(b.setup_token),await digest(env.SETUP_TOKEN)))fail(403,'初始化口令不正确。');
  const name=username(b.username),display=displayName(b.display_name),password=validPassword(b.password);
  if(await env.DB.prepare('SELECT id FROM setup_lock WHERE id=1').first())fail(409,'管理员已经创建，请直接登录。');
  const salt=random(16),hash=await passwordHash(password,salt,env.APP_SECRET),id=crypto.randomUUID();
  try{await env.DB.batch([env.DB.prepare('INSERT INTO setup_lock(id) VALUES(1)'),env.DB.prepare('INSERT INTO users(id,username,display_name,role,student_id,salt,password_hash,active,must_change,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(id,name,display,'admin',null,salt,hash,1,0,now())]);}catch{fail(409,'初始化已完成或账号已存在，请登录。');}
  return response({ok:true});
 }
 if(path==='/api/login'&&request.method==='POST'){
  const b=await body(request),name=username(b.username);
  if(typeof b.password!=='string'||b.password.length>128)fail(400,'账号或密码不正确。');
  await rateLimit(env,'ip',request.headers.get('cf-connecting-ip')||'unknown',40);
  await rateLimit(env,'account',name,12);
  const u=await env.DB.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').bind(name).first();
  if(!await verifyPassword(env,u,b.password)||!u.active)fail(401,'账号或密码不正确。');
  return response({user:publicUser(u),redirect:u.must_change?'/account':'/'},200,{'Set-Cookie':await issueSession(env,u)});
 }
 const user=await currentUser(request,env);if(!user)fail(401,'请先登录。');
 if(path==='/api/me'&&request.method==='GET')return response({user:publicUser(user)});
 if(path==='/api/logout'&&request.method==='POST'){
  // Revoke only this browser session.
  const token=(request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||'';
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();
  return response({ok:true},200,{'Set-Cookie':cookie('',0)});
 }
 if(path==='/api/password'&&request.method==='POST'){
  await rateLimit(env,'password',user.id,8);
  const b=await body(request),password=validPassword(b.password);
  if(typeof b.current_password!=='string'||b.current_password.length>128||!await verifyPassword(env,user,b.current_password))fail(400,'当前密码不正确。');
  if(b.current_password===password)fail(400,'新密码需要与当前密码不同。');
  const salt=random(16),hash=await passwordHash(password,salt,env.APP_SECRET);
  await env.DB.batch([env.DB.prepare('UPDATE users SET salt=?,password_hash=?,must_change=0 WHERE id=?').bind(salt,hash,user.id),env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(user.id)]);
  return response({ok:true},200,{'Set-Cookie':await issueSession(env,user)});
 }
 if(user.must_change)fail(403,'请先修改初始密码。');
 if(path==='/api/reports'&&request.method==='GET'){
  const rows=user.role==='admin'?await env.DB.prepare('SELECT payload FROM reports ORDER BY student_id').all():await env.DB.prepare('SELECT payload FROM reports WHERE student_id=?').bind(user.student_id).all();
  return response({reports:rows.results.map(r=>JSON.parse(r.payload))});
 }
 if(path.startsWith('/api/admin/')){
  if(user.role!=='admin')fail(403,'你没有账号管理权限。');
  if(path==='/api/admin/users'&&request.method==='GET')return response({users:(await env.DB.prepare('SELECT * FROM users ORDER BY created_at,username').all()).results.map(publicUser),students:(await env.DB.prepare('SELECT student_id,name FROM reports ORDER BY student_id').all()).results});
  if(path==='/api/admin/users'&&request.method==='POST'){
   const b=await body(request),name=username(b.username),display=displayName(b.display_name),password=validPassword(b.password);
   if(typeof b.student_id!=='string'||!await env.DB.prepare('SELECT student_id FROM reports WHERE student_id=?').bind(b.student_id).first())fail(400,'请选择有效的学生报告。');
   const salt=random(16),hash=await passwordHash(password,salt,env.APP_SECRET);
   try{await env.DB.prepare('INSERT INTO users(id,username,display_name,role,student_id,salt,password_hash,active,must_change,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),name,display,'student',b.student_id,salt,hash,1,1,now()).run();}catch{fail(409,'账号已存在，请换一个账号名。');}
   return response({ok:true},201);
  }
  const match=path.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)$/);
  if(match&&request.method==='PATCH'){
   const target=await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(match[1]).first();
   if(!target||target.role==='admin')fail(400,'此处只能修改学生账号。');
   const b=await body(request),updates=[],params=[];
   if('active'in b){if(typeof b.active!=='boolean')fail(400,'账号状态不正确。');updates.push('active=?');params.push(b.active?1:0);}
   if('student_id'in b){if(typeof b.student_id!=='string'||!await env.DB.prepare('SELECT student_id FROM reports WHERE student_id=?').bind(b.student_id).first())fail(400,'请选择有效的学生报告。');updates.push('student_id=?');params.push(b.student_id);}
   if('password'in b){const salt=random(16);const hash=await passwordHash(validPassword(b.password),salt,env.APP_SECRET);updates.push('salt=?','password_hash=?','must_change=1');params.push(salt,hash);}
   if(!updates.length)fail(400,'没有需要保存的修改。');
   await env.DB.batch([env.DB.prepare('UPDATE users SET '+updates.join(',')+' WHERE id=?').bind(...params,target.id),env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id)]);
   return response({ok:true});
  }
 }
 fail(404,'未找到此功能。');
}
export default {
 async fetch(request,env,ctx){
  let result;
  try{
   const url=new URL(request.url);
   if(!env.DB||!env.APP_SECRET||env.APP_SECRET.length<32)fail(503,'服务尚未完成配置。');
   if(url.pathname.startsWith('/api/'))result=await api(request,env,url);
   else if(!['GET','HEAD'].includes(request.method))fail(405,'不支持此操作。');
   else if(url.pathname==='/login')result=html(page('login'));
   else if(url.pathname==='/setup')result=html(page('setup'));
   else{
    const user=await currentUser(request,env);
    if(!user)result=redirect('/login');
    else if(user.must_change&&url.pathname!=='/account')result=redirect('/account');
    else if(url.pathname==='/account')result=html(page('account',publicUser(user)));
    else if(url.pathname==='/admin')result=user.role==='admin'?html(page('admin',publicUser(user))):new Response('无访问权限',{status:403});
    else if(url.pathname==='/'){
     const rows=user.role==='admin'?await env.DB.prepare('SELECT payload FROM reports ORDER BY student_id').all():await env.DB.prepare('SELECT payload FROM reports WHERE student_id=?').bind(user.student_id).all();
     if(!rows.results.length)result=html(page('empty',publicUser(user)));
     else result=html(reportTemplate.replace('__VIEWER_JSON__',()=>safeJSON(publicUser(user))).replace('__STUDENTS_JSON__',()=>safeJSON(rows.results.map(r=>JSON.parse(r.payload)))));
    }else result=new Response('页面不存在',{status:404});
   }
   if(ctx&&Math.random()<0.02)ctx.waitUntil(env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE expires_at<?').bind(now()),env.DB.prepare('DELETE FROM rate_limits WHERE expires_at<?').bind(now())]));
  }catch(e){result=response({error:e.status?e.message:'服务暂时无法完成请求，请稍后重试。'},e.status||500);}
  const headers=new Headers(result.headers);
  headers.set('Cache-Control','private, no-store, max-age=0');headers.set('Pragma','no-cache');
  headers.set('X-Content-Type-Options','nosniff');headers.set('Referrer-Policy','no-referrer');headers.set('X-Frame-Options','DENY');
  headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'self' about:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  return new Response(request.method==='HEAD'?null:result.body,{status:result.status,headers});
 }
};
