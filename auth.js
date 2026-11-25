const enc=new TextEncoder();
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");
const digest=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
const random=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
const same=(a,b)=>{if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let v=0;for(let i=0;i<a.length;i++)v|=a.charCodeAt(i)^b.charCodeAt(i);return v===0};
const derive=async(p,s)=>{const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(s),iterations:100000,hash:"SHA-256"},k,256))};
const json=(data,status=200,extra={})=>Response.json(data,{status,headers:{"Cache-Control":"no-store",...extra}});
const cookie=(t,age)=>"fp_session="+t+"; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age="+age;
async function schema(db){await db.batch([db.prepare("CREATE TABLE IF NOT EXISTS fp_users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','player')))"),db.prepare("CREATE TABLE IF NOT EXISTS fp_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL)"),db.prepare("CREATE TABLE IF NOT EXISTS fp_attempts (key TEXT PRIMARY KEY, n INTEGER NOT NULL, expires INTEGER NOT NULL)")])}
async function session(req,db){const t=(req.headers.get("Cookie")||"").match(/(?:^|;\s*)fp_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!t)return null;return db.prepare("SELECT u.username,u.role FROM fp_sessions s JOIN fp_users u ON u.username=s.username WHERE s.token_hash=? AND s.expires>?").bind(await digest(t),Date.now()).first()}

const sections=["calendario","classifica","rose","statistiche","formazioni-altrui","what-if","archivio","albo","precedenti","montepremi","regole","accessi"];
const players=["alfonso","cepe","daniele","fabrizio","michele","paolo","tomaso"];
async function permissionSchema(db){await db.batch([db.prepare("CREATE TABLE IF NOT EXISTS fp_levels (username TEXT PRIMARY KEY, level INTEGER NOT NULL CHECK(level IN (1,2)), enabled INTEGER NOT NULL DEFAULT 1)"),db.prepare("CREATE TABLE IF NOT EXISTS fp_visibility (level INTEGER NOT NULL CHECK(level IN (1,2)), section TEXT NOT NULL, allowed INTEGER NOT NULL CHECK(allowed IN (0,1)), PRIMARY KEY(level,section))"),db.prepare("CREATE TABLE IF NOT EXISTS fp_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created INTEGER NOT NULL)")])}
async function permissions(db,u){if(!u)return null;if(u.role==="admin")return {...u,level:3,views:sections};const row=await db.prepare("SELECT level,enabled FROM fp_levels WHERE username=?").bind(u.username).first();if(row?.enabled===0)return null;const level=row?.level||1;const v=await db.prepare("SELECT section,allowed FROM fp_visibility WHERE level=?").bind(level).all();const map=new Map(v.results.map(x=>[x.section,x.allowed]));return {...u,level,views:sections.filter(x=>map.has(x)?map.get(x)===1:!["accessi","formazioni-altrui"].includes(x))}}
async function manage(req,db,path){const u=await permissions(db,await session(req,db));if(u?.level!==3)return json({error:"Accesso riservato"},403);
if(path==="/api/auth/permissions"&&req.method==="GET"){const l=await db.prepare("SELECT u.username,l.level,l.enabled FROM fp_users u LEFT JOIN fp_levels l ON u.username=l.username WHERE u.role='player'").all();const v=await db.prepare("SELECT level,section,allowed FROM fp_visibility").all();return json({players:players.map(username=>{const row=l.results.find(x=>x.username===username);return {username,created:!!row,level:row?.level||1,enabled:row?.enabled!==0}}),sections,visibility:v.results})}
if(req.method!=="POST"||req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Richiesta non consentita"},403);
const raw=await req.text();if(raw.length>8192)return json({error:"Richiesta troppo grande"},413);let b;try{b=JSON.parse(raw)}catch{return json({error:"Dati non validi"},400)}
const audit=(action,detail)=>db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,action,JSON.stringify(detail),Date.now());
if(path==="/api/auth/visibility"){if(![1,2].includes(b.level)||!sections.includes(b.section)||typeof b.allowed!=="boolean")return json({error:"Permesso non valido"},400);await db.batch([db.prepare("INSERT INTO fp_visibility VALUES (?,?,?) ON CONFLICT(level,section) DO UPDATE SET allowed=excluded.allowed").bind(b.level,b.section,+b.allowed),audit("visibility",b)]);return json({ok:true})}
if(path==="/api/auth/account"){if(!players.includes(b.username)||![1,2].includes(b.level)||typeof b.enabled!=="boolean")return json({error:"Account non valido"},400);const existing=await db.prepare("SELECT username FROM fp_users WHERE username=? AND role='player'").bind(b.username).first();const ops=[];if(b.password!==undefined){if(typeof b.password!=="string"||b.password.length<12||b.password.length>128)return json({error:"Password: minimo 12 caratteri"},400);const salt=random(),hash=await derive(b.password,salt);ops.push(db.prepare("INSERT INTO fp_users VALUES (?,?,?,'player') ON CONFLICT(username) DO UPDATE SET salt=excluded.salt,password_hash=excluded.password_hash WHERE role='player'").bind(b.username,salt,hash));ops.push(db.prepare("DELETE FROM fp_sessions WHERE username=?").bind(b.username))}else if(!existing)return json({error:"Imposta una password iniziale"},400);ops.push(db.prepare("INSERT INTO fp_levels VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET level=excluded.level,enabled=excluded.enabled").bind(b.username,b.level,+b.enabled));if(!b.enabled)ops.push(db.prepare("DELETE FROM fp_sessions WHERE username=?").bind(b.username));ops.push(audit("account",{username:b.username,level:b.level,enabled:b.enabled,passwordChanged:b.password!==undefined}));await db.batch(ops);return json({ok:true})}
return json({error:"Funzione non disponibile"},404)}



async function dailyStats(req,db,u,path){
await db.prepare("CREATE TABLE IF NOT EXISTS fp_daily_stats (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated INTEGER NOT NULL)").run();
if(path!=="/api/auth/stats/import"||req.method!=="POST"||u.level!==3||req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Accesso riservato"},403);
if(Number(req.headers.get("Content-Length")||0)>200000)return json({error:"File troppo grande"},413);
const raw=await req.text();if(raw.length>200000)return json({error:"File troppo grande"},413);
let d;try{d=JSON.parse(raw)}catch{return json({error:"JSON non valido"},400)}
const row=await db.prepare("SELECT payload FROM fp_roster_snapshot WHERE id=1").first();if(!row)return json({error:"Importare prima le rose"},409);
const ids=new Set(JSON.parse(row.payload).players.map(p=>p.id));if(d.season!=="2026/27"||d.through!==12||!Array.isArray(d.players)||d.players.length!==200)return json({error:"Attesi 200 giocatori e 12 giornate"},400);
for(const p of d.players){if(!ids.delete(p.id)||!Array.isArray(p.history)||p.history.length!==12||!p.history.every(q=>q===null||(Array.isArray(q)&&q.length===3&&["T","S","-"].includes(q[0])&&(q[1]===null||Number.isFinite(q[1]))&&(q[2]===null||Number.isFinite(q[2])))))return json({error:"Dati non validi"},400)}
await db.batch([db.prepare("INSERT INTO fp_daily_stats VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated=excluded.updated").bind(JSON.stringify(d),Date.now()),db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,"stats_import","G1-G12",Date.now())]);return json({ok:true,count:200,through:12});
}
async function enrichStats(db,data,day){
await db.prepare("CREATE TABLE IF NOT EXISTS fp_daily_stats (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated INTEGER NOT NULL)").run();
const row=await db.prepare("SELECT payload FROM fp_daily_stats WHERE id=1").first();if(!row)return data;
const d=JSON.parse(row.payload),through=Math.min(d.through,day-1),map=new Map(d.players.map(p=>[p.id,p.history]));
const avg=a=>{const v=a.filter(q=>q&&Number.isFinite(q[2])).map(q=>q[2]);return v.length?v.reduce((a,b)=>a+b,0)/v.length:null};
return {...data,through,source:"Fantapunti Gazzetta",players:data.players.map(p=>{const hist=map.get(p.id).slice(0,through);return {...p,fm:avg(hist),fm5:avg(hist.slice(-5)),history:hist.map(q=>q?q[0]:"?"),daily:hist}})};
}

async function rosterApi(req,db,path){
const u=await permissions(db,await session(req,db));if(!u)return json({error:"Effettua l'accesso"},401);
if(path==="/api/auth/stats/import")return dailyStats(req,db,u,path);
await db.prepare("CREATE TABLE IF NOT EXISTS fp_roster_snapshot (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated INTEGER NOT NULL)").run();
if(req.method==="GET"&&path==="/api/auth/rosters"){
const url=new URL(req.url),owner=url.searchParams.get("owner"),purpose=url.searchParams.get("purpose")||"rose";
if(!["rose","statistiche","formazione"].includes(purpose))return json({error:"Richiesta non valida"},400);
const full=u.level===3||u.views.includes(purpose==="formazione"?"formazioni-altrui":purpose);
if(purpose!=="formazione"&&!full)return json({error:"Sezione non autorizzata"},403);
if(purpose==="formazione"&&owner&&owner!==u.username&&!full&&u.level!==2)return json({error:"Accesso non autorizzato"},403);
const row=await db.prepare("SELECT payload FROM fp_roster_snapshot WHERE id=1").first();
if(!row)return json({players:[],through:null,user:u.username,level:u.level});
const requested=Number(url.searchParams.get("day")||13);const day=Number.isInteger(requested)&&requested>=12&&requested<=32?requested:13;const data=await enrichStats(db,JSON.parse(row.payload),day);return json({source:data.source,through:data.through,players:data.players.filter(p=>purpose==="formazione"?p.owner===(owner||u.username):!owner||p.owner===owner),user:u.username,level:u.level});
}
if(path!=="/api/auth/rosters/import"||req.method!=="POST"||u.level!==3||req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Accesso riservato"},403);
if(Number(req.headers.get("Content-Length")||0)>150000)return json({error:"File troppo grande"},413);
const raw=await req.text();if(raw.length>150000)return json({error:"File troppo grande"},413);
let d;try{d=JSON.parse(raw)}catch{return json({error:"File JSON non valido"},400)}
const owners=["marco",...players],roles={P:3,D:8,C:8,A:6};
if(d?.season!=="2026/27"||d.through!==11||!Array.isArray(d.players)||d.players.length!==200)return json({error:"Attesi 200 giocatori, stagione 2026/27, dati G1–11"},400);
const ids=new Set(),names=new Set();
for(const p of d.players){if(!p||!Number.isInteger(p.id)||ids.has(p.id)||typeof p.name!=="string"||!p.name.trim()||p.name.length>100||names.has(p.name)||typeof p.team!=="string"||!/^[A-Z]{2,4}$/.test(p.team)||!owners.includes(p.owner)||!Object.hasOwn(roles,p.role)||!Number.isFinite(p.price)||p.price<0||!Array.isArray(p.history)||p.history.length!==11||!p.history.every(v=>["T","S","-"].includes(v))||!["fm","fm5","appearances","goals","assists","conceded"].every(k=>p[k]===null||Number.isFinite(p[k])))return json({error:"Dati giocatore non validi"},400);ids.add(p.id);names.add(p.name)}
for(const owner of owners){const rr=d.players.filter(p=>p.owner===owner);if(rr.length!==25||rr.reduce((a,p)=>a+p.price,0)!==500||Object.entries(roles).some(([k,n])=>rr.filter(p=>p.role===k).length!==n))return json({error:"Rosa non valida: "+owner},400)}
const existing=await db.prepare("SELECT id FROM fp_roster_snapshot WHERE id=1").first();if(existing)return json({error:"Rose già importate. Sostituzione non consentita."},409);
await db.batch([db.prepare("INSERT INTO fp_roster_snapshot VALUES (1,?,?)").bind(JSON.stringify(d),Date.now()),db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,"roster_import",JSON.stringify({count:200,through:11}),Date.now())]);return json({ok:true,count:200});
}

export async function auth(req,env,path){
const db=env.DB;try{await schema(db);await permissionSchema(db);
if(path==='/api/auth/rosters'||path==='/api/auth/rosters/import'||path==='/api/auth/stats/import')return await rosterApi(req,db,path);
if(['/api/auth/permissions','/api/auth/visibility','/api/auth/account'].includes(path))return await manage(req,db,path);
if(path==="/api/auth/me"&&req.method==="GET"){const u=await permissions(db,await session(req,db));const admin=await db.prepare("SELECT 1 AS present FROM fp_users WHERE role='admin' LIMIT 1").first();return json({user:u,setup:!admin})}
if(req.method!=="POST")return json({error:"Metodo non consentito"},405);
if(req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Richiesta non consentita"},403);
if(path==="/api/auth/logout"){const t=(req.headers.get("Cookie")||"").match(/(?:^|;\s*)fp_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(t)await db.prepare("DELETE FROM fp_sessions WHERE token_hash=?").bind(await digest(t)).run();return json({ok:true},200,{"Set-Cookie":cookie("",0)})}
if(Number(req.headers.get("Content-Length")||0)>4096)return json({error:"Richiesta troppo grande"},413);
const raw=await req.text();if(raw.length>4096)return json({error:"Richiesta troppo grande"},413);let b;try{b=JSON.parse(raw)}catch{return json({error:"Dati non validi"},400)}
const username=typeof b.username==="string"?b.username.trim().toLowerCase():"";const p=b.password;if(!/^[a-z0-9_-]{2,30}$/.test(username)||typeof p!=="string"||p.length<12||p.length>128)return json({error:"Nome utente o password non validi (minimo 12 caratteri)."},400);
const now=Date.now();const ip=req.headers.get("CF-Connecting-IP")||"unknown";const key=await digest(ip+"|"+username);const a=await db.prepare("INSERT INTO fp_attempts VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET n=CASE WHEN expires<=? THEN 1 ELSE n+1 END,expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING n").bind(key,now+900000,now,now).first();if(a.n>8)return json({error:"Troppi tentativi. Riprova tra 15 minuti."},429);
let u;
if(path==="/api/auth/setup"){
if(username!=="marco"||typeof b.code!=="string"||!env.ADMIN_SETUP_CODE||env.ADMIN_SETUP_CODE.length<24||!same(await digest(b.code),await digest(env.ADMIN_SETUP_CODE)))return json({error:"Codice di attivazione non valido."},403);
const salt=random(),hash=await derive(p,salt);
const result=await db.prepare("INSERT INTO fp_users (username,salt,password_hash,role) SELECT ?,?,?,'admin' WHERE NOT EXISTS (SELECT 1 FROM fp_users WHERE role='admin')").bind(username,salt,hash).run();if(result.meta.changes!==1)return json({error:"Amministratore già attivato."},409);u={username,role:"admin"};
}else if(path==="/api/auth/login"){const row=await db.prepare("SELECT * FROM fp_users WHERE username=?").bind(username).first();const hash=await derive(p,row?.salt||"invalid-user-placeholder");if(!row||!same(hash,row.password_hash))return json({error:"Credenziali non valide."},401);u={username:row.username,role:row.role};}
else return json({error:"Funzione non disponibile"},404);
u=await permissions(db,u);if(!u)return json({error:"Account disattivato"},403);const t=random();await db.batch([db.prepare("DELETE FROM fp_attempts WHERE key=? OR expires<=?").bind(key,now),db.prepare("DELETE FROM fp_sessions WHERE expires<=?").bind(now),db.prepare("INSERT INTO fp_sessions VALUES (?,?,?)").bind(await digest(t),u.username,now+604800000)]);return json({user:u},200,{"Set-Cookie":cookie(t,604800)});
}catch(e){return json({error:"Accesso temporaneamente non disponibile."},503)}}
