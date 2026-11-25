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
export async function auth(req,env,path){
const db=env.DB;try{await schema(db);
if(path==="/api/auth/me"&&req.method==="GET"){const u=await session(req,db);const admin=await db.prepare("SELECT 1 AS present FROM fp_users WHERE role='admin' LIMIT 1").first();return json({user:u,setup:!admin})}
if(req.method!=="POST")return json({error:"Metodo non consentito"},405);
if(req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Richiesta non consentita"},403);
if(path==="/api/auth/logout"){const t=(req.headers.get("Cookie")||"").match(/(?:^|;\s*)fp_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(t)await db.prepare("DELETE FROM fp_sessions WHERE token_hash=?").bind(await digest(t)).run();return json({ok:true},200,{"Set-Cookie":cookie("",0)})}
if(Number(req.headers.get("Content-Length")||0)>4096)return json({error:"Richiesta troppo grande"},413);
const raw=await req.text();if(raw.length>4096)return json({error:"Richiesta troppo grande"},413);let b;try{b=JSON.parse(raw)}catch{return json({error:"Dati non validi"},400)}
const username=typeof b.username==="string"?b.username.trim().toLowerCase():"";const p=b.password;if(!/^[a-z0-9_-]{2,30}$/.test(username)||typeof p!=="string"||p.length<12||p.length>128)return json({error:"Nome utente o password non validi (minimo 12 caratteri)."},400);
const now=Date.now();const ip=req.headers.get("CF-Connecting-IP")||"unknown";const key=await digest(ip+"|"+username);const a=await db.prepare("INSERT INTO fp_attempts VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET n=CASE WHEN expires<=? THEN 1 ELSE n+1 END,expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING n").bind(key,now+900000,now,now).first();if(a.n>8)return json({error:"Troppi tentativi. Riprova tra 15 minuti."},429);
let u;
if(path==="/api/auth/setup"){
if(username!=="marco"||typeof b.code!=="string"||!same(await digest(b.code),"ecac495f20390865d9dbb61ebc939a1034a483f37b9153cf24189ccd9d1d7737"))return json({error:"Codice di attivazione non valido."},403);
const salt=random(),hash=await derive(p,salt);
const result=await db.prepare("INSERT INTO fp_users (username,salt,password_hash,role) SELECT ?,?,?,'admin' WHERE NOT EXISTS (SELECT 1 FROM fp_users WHERE role='admin')").bind(username,salt,hash).run();if(result.meta.changes!==1)return json({error:"Amministratore già attivato."},409);u={username,role:"admin"};
}else if(path==="/api/auth/login"){const row=await db.prepare("SELECT * FROM fp_users WHERE username=?").bind(username).first();const hash=await derive(p,row?.salt||"invalid-user-placeholder");if(!row||!same(hash,row.password_hash))return json({error:"Credenziali non valide."},401);u={username:row.username,role:row.role};}
else return json({error:"Funzione non disponibile"},404);
const t=random();await db.batch([db.prepare("DELETE FROM fp_attempts WHERE key=? OR expires<=?").bind(key,now),db.prepare("DELETE FROM fp_sessions WHERE expires<=?").bind(now),db.prepare("INSERT INTO fp_sessions VALUES (?,?,?)").bind(await digest(t),u.username,now+604800000)]);return json({user:u},200,{"Set-Cookie":cookie(t,604800)});
}catch(e){return json({error:"Accesso temporaneamente non disponibile."},503)}}
