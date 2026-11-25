import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync,existsSync } from 'node:fs';
import vm from 'node:vm';
import worker from '../src/worker.js';
import { reportTemplate } from '../src/report-template.js';
import { page } from '../src/screens.js';

function database(){
 const db=new DatabaseSync(':memory:');
 db.exec(readFileSync(new URL('../migrations/0001_init.sql',import.meta.url),'utf8'));
 const prepare=sql=>({args:[],bind(...args){this.args=args;return this;},async first(){return db.prepare(sql).get(...this.args)||null;},async all(){return {results:db.prepare(sql).all(...this.args)};},async run(){return db.prepare(sql).run(...this.args);}});
 return {raw:db,prepare,async batch(statements){db.exec('BEGIN');try{const rows=[];for(const s of statements)rows.push(await s.run());db.exec('COMMIT');return rows;}catch(e){db.exec('ROLLBACK');throw e;}}};
}
const initial='Initial-password-123!',changed='Changed-password-456!';
const origin='https://review.example';
function client(env){return async function call(path,method='GET',data,cookie,extra={}){
 const request=new Request(origin+path,{method,headers:{Origin:origin,'CF-Connecting-IP':'192.0.2.1',...(data?{'Content-Type':'application/json'}:{}),...(cookie?{Cookie:cookie}:{}),...extra},body:data?JSON.stringify(data):undefined});
 const response=await worker.fetch(request,env);
 const text=await response.text();return {status:response.status,headers:response.headers,text,json:()=>JSON.parse(text),cookie:response.headers.get('set-cookie')?.split(';')[0]};
};}
async function fixture(){
 const DB=database(),env={DB,APP_SECRET:'x'.repeat(64),SETUP_TOKEN:'setup-'+ 'y'.repeat(64)},call=client(env);
 for(const [id,name] of [['s0','Student Alpha'],['s1','Student Bravo']])await DB.prepare('INSERT INTO reports VALUES(?,?,?)').bind(id,name,JSON.stringify({id,name,private_marker:id+'-private-content'})).run();
 const setup=await call('/api/setup','POST',{setup_token:env.SETUP_TOKEN,username:'admin',display_name:'Admin',password:initial});assert.equal(setup.status,200);
 const login=await call('/api/login','POST',{username:'admin',password:initial});assert.equal(login.status,200);const admin=login.cookie;
 for(const [username,student_id] of [['alpha','s0'],['bravo','s1']])assert.equal((await call('/api/admin/users','POST',{username,display_name:username,student_id,password:initial,role:'admin'},admin)).status,201);
 return {env,call,admin,DB};
}
async function student(call,name){const r=await call('/api/login','POST',{username:name,password:initial});assert.equal(r.status,200);const p=await call('/api/password','POST',{current_password:initial,password:changed},r.cookie);assert.equal(p.status,200);return p.cookie;}

test('anonymous users cannot retrieve data; setup is one-time and origin protected',async()=>{
 const {env,call}=await fixture();
 assert.equal((await call('/api/reports')).status,401);
 const root=await call('/');assert.equal(root.status,303);assert.equal(root.headers.get('location'),'/login');assert.ok(!root.text.includes('private-content'));
 assert.equal((await call('/api/setup','POST',{setup_token:'incorrect',username:'other',display_name:'Other',password:initial})).status,403);
 assert.equal((await call('/api/setup','POST',{setup_token:env.SETUP_TOKEN,username:'other',display_name:'Other',password:initial})).status,409);
 assert.equal((await call('/api/login','POST',{username:'admin',password:initial},null,{Origin:'https://evil.example'})).status,403);
});
test('first password change is required, replaces sessions, and student cannot elevate access',async()=>{
 const {call,admin}=await fixture();
 const first=await call('/api/login','POST',{username:'alpha',password:initial});
 assert.equal((await call('/api/reports','GET',null,first.cookie)).status,403);
 assert.equal((await call('/','GET',null,first.cookie)).headers.get('location'),'/account');
 const change=await call('/api/password','POST',{current_password:initial,password:changed},first.cookie);assert.equal(change.status,200);
 assert.equal((await call('/api/me','GET',null,first.cookie)).status,401);
 const cookie=change.cookie;
 for(const path of ['/api/reports','/api/reports?student_id=s1&role=admin']){
  const r=await call(path,'GET',null,cookie);assert.equal(r.status,200);assert.equal(r.json().reports.length,1);assert.equal(r.json().reports[0].id,'s0');assert.ok(!r.text.includes('s1-private-content'));
 }
 assert.equal((await call('/api/admin/users','GET',null,cookie)).status,403);
 assert.equal((await call('/admin','GET',null,cookie)).status,403);
 const html=await call('/','GET',null,cookie);assert.equal(html.status,200);assert.ok(html.text.includes('s0-private-content'));assert.ok(!html.text.includes('Student Bravo'));assert.ok(!html.text.includes('s1-private-content'));
 assert.match(html.headers.get('cache-control'),/no-store/);
 assert.equal((await call('/api/me','GET',null,cookie)).json().user.role,'student');
 const users=await call('/api/admin/users','GET',null,admin);assert.ok(!users.text.includes('password_hash'));assert.ok(!users.text.includes('"salt"'));
 assert.match(change.headers.get('set-cookie'),/Secure; HttpOnly; SameSite=Strict/);
 assert.equal((await call('/api/reports','GET',null,admin)).json().reports.length,2);
});
test('reassigning, disabling and resetting an account revoke its existing sessions',async()=>{
 const {call,admin}=await fixture();let cookie=await student(call,'alpha');
 const id=(await call('/api/admin/users','GET',null,admin)).json().users.find(u=>u.username==='alpha').id;
 const patch=data=>call('/api/admin/users/'+id,'PATCH',data,admin);
 assert.equal((await patch({student_id:'s1'})).status,200);
 assert.equal((await call('/api/reports','GET',null,cookie)).status,401);
 cookie=(await call('/api/login','POST',{username:'alpha',password:changed})).cookie;
 assert.equal((await call('/api/reports','GET',null,cookie)).json().reports[0].id,'s1');
 assert.equal((await patch({active:false})).status,200);
 assert.equal((await call('/api/me','GET',null,cookie)).status,401);
 assert.equal((await call('/api/login','POST',{username:'alpha',password:changed})).status,401);
 assert.equal((await patch({active:true,password:initial})).status,200);
 const reset=await call('/api/login','POST',{username:'alpha',password:initial});assert.equal(reset.status,200);assert.equal(reset.json().redirect,'/account');
 assert.equal((await call('/api/reports','GET',null,reset.cookie)).status,403);
 assert.equal((await patch({student_id:{bad:true}})).status,400);
});
test('login rate limiting, expiration and logout are enforced on server',async()=>{
 const {call,DB}=await fixture();
 let cookie=await student(call,'alpha');
 assert.equal((await call('/api/logout','POST',{},cookie)).status,200);
 assert.equal((await call('/api/me','GET',null,cookie)).status,401);
 cookie=(await call('/api/login','POST',{username:'alpha',password:changed})).cookie;
 DB.raw.exec('UPDATE sessions SET expires_at=0');
 assert.equal((await call('/api/me','GET',null,cookie)).status,401);
 for(let i=0;i<12;i++)assert.equal((await call('/api/login','POST',{username:'unknown',password:'wrong'})).status,401);
 assert.equal((await call('/api/login','POST',{username:'unknown',password:'wrong'})).status,429);
});
test('all screens have syntactically valid scripts and escape user content',()=>{
 for(const kind of ['login','setup','account','admin','empty']){
  const html=page(kind,{display_name:'<script>bad()</script>',username:'<img>',role:'admin'});
  for(const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g))new vm.Script(match[1]);
  assert.ok(!html.includes('<script>bad()'));
 }
 assert.ok(!reportTemplate.includes('"private_marker"'));
});

const privateSeed=new URL('../private/initial-reports.sql',import.meta.url);
test('supplied individual reports render with no other student data or recommendations', {skip:!existsSync(privateSeed)},async()=>{
 const {DB,call,admin}=await fixture();
 DB.raw.exec(readFileSync(privateSeed,'utf8'));
 const records=DB.raw.prepare('SELECT payload FROM reports WHERE student_id NOT LIKE ?').all('never').map(r=>JSON.parse(r.payload)).filter(s=>s.suggested_examples);
 assert.equal(records.length,7);
 const noop=()=>{};
 function element(){return {innerHTML:'',textContent:'',style:{},classList:{add:noop,remove:noop,toggle:noop},addEventListener:noop,setAttribute:noop,append:noop,querySelectorAll:()=>[]};}
 for(const [i,record] of records.entries()){
  const username='viewer'+i;
  assert.equal((await call('/api/admin/users','POST',{username,display_name:'Viewer',student_id:record.id,password:initial},admin)).status,201);
  const cookie=await student(call,username);
  const r=await call('/','GET',null,cookie);assert.equal(r.status,200);
  for(const other of records.filter(s=>s.id!==record.id))assert.ok(!r.text.includes(other.name),'another student name must never reach this browser');
  const els={};const document={getElementById:id=>els[id]??(els[id]=element()),createElement:element,querySelectorAll:()=>[],addEventListener:noop,body:element(),head:element()};
  const context={document,window:{scrollTo:noop,addEventListener:noop},location:{hash:'',replace:noop},console,requestAnimationFrame:noop};vm.createContext(context);
  for(const match of r.text.matchAll(/<script>([\s\S]*?)<\/script>/g))vm.runInContext(match[1],context);
  assert.equal(vm.runInContext('students.length',context),1);
  assert.equal(vm.runInContext('students[0].id',context),record.id);
  assert.equal(vm.runInContext('Object.keys(studentExamples).length',context),1);
  assert.equal(vm.runInContext('overallParts.length',context),1);
  assert.ok(vm.runInContext('studentView(students[0])',context).includes(record.name));
  assert.equal(typeof vm.runInContext('overview()',context),'string');
  assert.equal(els.exportOverallButton.hidden,true);
  assert.equal(els.accountAdminLink.hidden,true);
 }
});
