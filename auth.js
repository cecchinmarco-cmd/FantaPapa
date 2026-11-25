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

const sections=["formazione-presenze","formazione-fm","formazione-fm5","calendario","classifica","rose","statistiche","formazioni-altrui","what-if","archivio","albo","precedenti","montepremi","regole","accessi"];
const players=["alfonso","cepe","daniele","fabrizio","michele","paolo","tomaso"];
async function permissionSchema(db){await db.batch([db.prepare("CREATE TABLE IF NOT EXISTS fp_user_visibility (username TEXT NOT NULL, section TEXT NOT NULL, allowed INTEGER NOT NULL CHECK(allowed IN (0,1)), PRIMARY KEY(username,section))"),db.prepare("CREATE TABLE IF NOT EXISTS fp_levels (username TEXT PRIMARY KEY, level INTEGER NOT NULL CHECK(level IN (1,2)), enabled INTEGER NOT NULL DEFAULT 1)"),db.prepare("CREATE TABLE IF NOT EXISTS fp_visibility (level INTEGER NOT NULL CHECK(level IN (1,2)), section TEXT NOT NULL, allowed INTEGER NOT NULL CHECK(allowed IN (0,1)), PRIMARY KEY(level,section))"),db.prepare("CREATE TABLE IF NOT EXISTS fp_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created INTEGER NOT NULL)")])}
async function permissions(db,u){if(!u)return null;if(u.role==="admin")return {...u,level:3,views:sections};const row=await db.prepare("SELECT level,enabled FROM fp_levels WHERE username=?").bind(u.username).first();if(row?.enabled===0)return null;const level=row?.level||1;const v=await db.prepare("SELECT section,allowed FROM fp_visibility WHERE level=?").bind(level).all();const map=new Map(v.results.map(x=>[x.section,x.allowed]));const individual=await db.prepare("SELECT section,allowed FROM fp_user_visibility WHERE username=?").bind(u.username).all();for(const item of individual.results)map.set(item.section,item.allowed);return {...u,level,views:sections.filter(x=>map.has(x)?map.get(x)===1:!["accessi","formazioni-altrui","formazione-presenze","formazione-fm","formazione-fm5"].includes(x))}}
async function manage(req,db,path){const u=await permissions(db,await session(req,db));if(u?.level!==3)return json({error:"Accesso riservato"},403);
if(path==="/api/auth/permissions"&&req.method==="GET"){const l=await db.prepare("SELECT u.username,l.level,l.enabled FROM fp_users u LEFT JOIN fp_levels l ON u.username=l.username WHERE u.role='player'").all();const v=await db.prepare("SELECT level,section,allowed FROM fp_visibility").all();const individual=await db.prepare("SELECT username,section,allowed FROM fp_user_visibility").all();return json({individual:individual.results,players:players.map(username=>{const row=l.results.find(x=>x.username===username);return {username,created:!!row,level:row?.level||1,enabled:row?.enabled!==0}}),sections,visibility:v.results})}
if(req.method!=="POST"||req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Richiesta non consentita"},403);
const raw=await req.text();if(raw.length>8192)return json({error:"Richiesta troppo grande"},413);let b;try{b=JSON.parse(raw)}catch{return json({error:"Dati non validi"},400)}
const audit=(action,detail)=>db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,action,JSON.stringify(detail),Date.now());
if(path==="/api/auth/visibility"){if(![1,2].includes(b.level)||!sections.includes(b.section)||typeof b.allowed!=="boolean")return json({error:"Permesso non valido"},400);await db.batch([db.prepare("INSERT INTO fp_visibility VALUES (?,?,?) ON CONFLICT(level,section) DO UPDATE SET allowed=excluded.allowed").bind(b.level,b.section,+b.allowed),audit("visibility",b)]);return json({ok:true})}
if(path==="/api/auth/individual-visibility"){if(!players.includes(b.username)||!["formazione-presenze","formazione-fm","formazione-fm5"].includes(b.section)||!(b.allowed===null||typeof b.allowed==="boolean"))return json({error:"Permesso individuale non valido"},400);const op=b.allowed===null?db.prepare("DELETE FROM fp_user_visibility WHERE username=? AND section=?").bind(b.username,b.section):db.prepare("INSERT INTO fp_user_visibility VALUES (?,?,?) ON CONFLICT(username,section) DO UPDATE SET allowed=excluded.allowed").bind(b.username,b.section,+b.allowed);await db.batch([op,audit("individual_visibility",b)]);return json({ok:true})}
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
const requested=Number(url.searchParams.get("day")||13);const day=Number.isInteger(requested)&&requested>=12&&requested<=32?requested:13;const allowed={presence:u.level===3||u.views.includes("formazione-presenze"),fm:u.level===3||u.views.includes("formazione-fm"),fm5:u.level===3||u.views.includes("formazione-fm5")};const base=JSON.parse(row.payload);const data=purpose==="formazione"&&!Object.values(allowed).some(Boolean)?base:await enrichStats(db,base,day);const result=data.players.filter(p=>purpose==="formazione"?p.owner===(owner||u.username):!owner||p.owner===owner).map(p=>{if(u.level===3)return p;const x={id:p.id,name:p.name,team:p.team,owner:p.owner,role:p.role,price:p.price};if(allowed.presence)x.history=p.daily?p.daily.map(q=>q?[q[0],Number.isFinite(q[1])&&Number.isFinite(q[2])?1:null]:null):p.history.map(v=>[v,null]);if(allowed.fm)x.fm=p.fm;if(allowed.fm5)x.fm5=p.fm5;if(purpose==="statistiche"){x.appearances=p.appearances;x.goals=p.goals;x.assists=p.assists;x.conceded=p.conceded}return x});return json({source:data.source,through:data.through,players:result,user:u.username,level:u.level,formationStats:allowed});
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


async function formationApi(req,db,path){
const u=await permissions(db,await session(req,db));if(!u)return json({error:"Effettua l'accesso"},401);
await db.batch([db.prepare("CREATE TABLE IF NOT EXISTS fp_deadlines (day INTEGER PRIMARY KEY, kickoff INTEGER NOT NULL)"),db.prepare("CREATE TABLE IF NOT EXISTS fp_formations (day INTEGER NOT NULL, owner TEXT NOT NULL, payload TEXT NOT NULL, updated INTEGER NOT NULL, actor TEXT NOT NULL, late INTEGER NOT NULL, PRIMARY KEY(day,owner))"),db.prepare("CREATE TABLE IF NOT EXISTS fp_formation_history (id INTEGER PRIMARY KEY AUTOINCREMENT, day INTEGER NOT NULL, owner TEXT NOT NULL, payload TEXT NOT NULL, updated INTEGER NOT NULL, actor TEXT NOT NULL, late INTEGER NOT NULL)")]);
await db.prepare("CREATE TABLE IF NOT EXISTS fp_override (day INTEGER PRIMARY KEY, until_ms INTEGER NOT NULL)").run();
// Official Serie A kickoffs through round 19, published 25 September 2026. Preserve administrator corrections.
const officialKickoffs=["2026-11-21T15:00:00+01:00","2026-11-27T20:45:00+01:00","2026-12-04T20:45:00+01:00","2026-12-11T20:45:00+01:00","2026-12-18T18:30:00+01:00","2027-01-02T12:30:00+01:00","2027-01-05T18:30:00+01:00","2027-01-09T15:00:00+01:00"];
await db.batch(officialKickoffs.map((t,i)=>db.prepare("INSERT OR IGNORE INTO fp_deadlines(day,kickoff) VALUES (?,?)").bind(i+1,Date.parse(t))));
const url=new URL(req.url),day=Number(url.searchParams.get("day")),owner=url.searchParams.get("owner")||u.username;
const allOwners=["marco",...players],validDay=n=>Number.isInteger(n)&&n>=1&&n<=21;

// Materialize inherited confirmations only after known official deadlines.
// Copy the last confirmed configuration, never invent an initial formation.
const nowMs=Date.now();
const closed=await db.prepare("SELECT day,kickoff FROM fp_deadlines WHERE kickoff+60000<=? ORDER BY day").bind(nowMs).all();
for(const d of closed.results){if(d.day<=1)continue;
await db.prepare("INSERT OR IGNORE INTO fp_formations(day,owner,payload,updated,actor,late) SELECT ?,p.owner,p.payload,?,'ufficio',0 FROM fp_formations p WHERE p.day=(SELECT MAX(q.day) FROM fp_formations q WHERE q.owner=p.owner AND q.day<?) AND p.day<? AND p.updated<=?").bind(d.day,d.kickoff+60000,d.day,d.day,d.kickoff+60000).run()}
if(path==="/api/auth/formation/status"&&req.method==="GET"){if(u.level!==3&&!u.views.includes("calendario"))return json({error:"Non autorizzato"},403);const rows=await db.prepare("SELECT day,owner,updated,actor,late FROM fp_formations").all();return json({rows:rows.results})}
if(path==="/api/auth/formation/deadlines"&&req.method==="GET"){const rows=await db.prepare("SELECT day,kickoff FROM fp_deadlines ORDER BY day").all();return json({rows:rows.results})}
if(!validDay(day)||!allOwners.includes(owner))return json({error:"Giornata o utente non valido"},400);
const canEdit=u.level===3||u.username===owner;
const canRead=canEdit||u.views.includes("formazioni-altrui");
const deadline=await db.prepare("SELECT kickoff FROM fp_deadlines WHERE day=?").bind(day).first();
const cutoff=deadline?deadline.kickoff+60000:null;
const override=await db.prepare("SELECT until_ms FROM fp_override WHERE day=?").bind(day).first();const extraordinary=u.level===3||u.level===2&&u.username===owner&&Number(override?.until_ms)>Date.now();
if(req.method==="GET"&&path==="/api/auth/formation"){if(!canRead)return json({error:"Non autorizzato"},403);const row=await db.prepare("SELECT payload,updated,actor,late FROM fp_formations WHERE day=? AND owner=?").bind(day,owner).first();const history=u.level===3?await db.prepare("SELECT id,updated,actor,late FROM fp_formation_history WHERE day=? AND owner=? ORDER BY id DESC LIMIT 20").bind(day,owner).all():null;return json({formation:row?{...row,payload:JSON.parse(row.payload)}:null,history:history?.results||[],cutoff,editable:canEdit&&cutoff!==null&&(extraordinary||Date.now()<cutoff),overrideUntil:override?.until_ms||null,level:u.level,owner})}
if(req.method!=="POST"||req.headers.get("Origin")!==url.origin)return json({error:"Richiesta non consentita"},403);
const raw=await req.text();if(raw.length>16000)return json({error:"Richiesta troppo grande"},413);let b;try{b=JSON.parse(raw)}catch{return json({error:"Dati non validi"},400)}
if(path==="/api/auth/formation/override"){if(u.level!==3||!Number.isInteger(b.minutes)||b.minutes<0||b.minutes>60)return json({error:"Finestra non valida"},400);const until=b.minutes?Date.now()+b.minutes*60000:0;await db.batch([db.prepare("INSERT INTO fp_override VALUES (?,?) ON CONFLICT(day) DO UPDATE SET until_ms=excluded.until_ms").bind(day,until),db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,"formation_override",JSON.stringify({day,until}),Date.now())]);return json({ok:true,until})}
if(path==="/api/auth/formation/deadlines"){if(u.level!==3||!Number.isSafeInteger(b.kickoff)||b.kickoff<1787000000000||b.kickoff>1823000000000)return json({error:"Scadenza non valida"},400);await db.batch([db.prepare("INSERT INTO fp_deadlines VALUES (?,?) ON CONFLICT(day) DO UPDATE SET kickoff=excluded.kickoff").bind(day,b.kickoff),db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,"deadline",JSON.stringify({day,kickoff:b.kickoff}),Date.now())]);return json({ok:true})}
if(path!=="/api/auth/formation"||!canEdit)return json({error:"Non autorizzato"},403);
if(cutoff===null)return json({error:"Impostare prima la scadenza ufficiale"},409);
const now=Date.now(),late=+(now>=cutoff);if(late&&!extraordinary)return json({error:"Consegna chiusa"},403);
const snapshot=await db.prepare("SELECT payload FROM fp_roster_snapshot WHERE id=1").first();if(!snapshot)return json({error:"Rose non disponibili"},409);
const roster=JSON.parse(snapshot.payload).players.filter(p=>p.owner===owner),mods=["3-4-3","4-3-3","4-4-2","3-5-2","5-3-2","4-5-1","5-4-1"];
if(!Array.isArray(b.modules)||!b.modules.length||new Set(b.modules).size!==b.modules.length||!b.modules.every(m=>mods.includes(m))||!b.order||!Array.isArray(b.exceptions)||!b.departments)return json({error:"Configurazione non valida"},400);
for(const role of ["P","D","C","A"]){const ids=roster.filter(p=>p.role===role).map(p=>p.id),o=b.order[role];if(!Array.isArray(o)||o.length!==ids.length||new Set(o).size!==ids.length||!o.every(id=>ids.includes(id)))return json({error:"Ordine rosa non valido"},400)}
if(new Set(b.exceptions.map(x=>x.id)).size!==b.exceptions.length||!b.exceptions.every(x=>roster.some(p=>p.id===x.id)&&["first","must"].includes(x.type)))return json({error:"Eccezioni individuali non valide"},400);
const firstRoles=b.exceptions.filter(x=>x.type==="first").map(x=>roster.find(p=>p.id===x.id).role);if(new Set(firstRoles).size!==firstRoles.length)return json({error:"È consentito un solo primo cambio per reparto."},400);
for(const role of ["A","C","D"]){const a=b.departments[role],valid=role==="A"?[1,2,3]:[3,4,5];if(!Array.isArray(a)||new Set(a).size!==a.length||!a.every(n=>valid.includes(n)))return json({error:"Eccezioni reparto non valide"},400)}
const payload=JSON.stringify({modules:b.modules,order:b.order,exceptions:b.exceptions,departments:b.departments});
await db.batch([db.prepare("INSERT INTO fp_formations VALUES (?,?,?,?,?,?) ON CONFLICT(day,owner) DO UPDATE SET payload=excluded.payload,updated=excluded.updated,actor=excluded.actor,late=excluded.late").bind(day,owner,payload,now,u.username,late),db.prepare("INSERT INTO fp_formation_history(day,owner,payload,updated,actor,late) VALUES (?,?,?,?,?,?)").bind(day,owner,payload,now,u.username,late),db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,"formation_confirm",JSON.stringify({day,owner,late}),now)]);
return json({ok:true,updated:now,actor:u.username,late});
}


async function resultsApi(req,db){
const u=await permissions(db,await session(req,db));if(!u)return json({error:"Effettua l'accesso"},401);
if(u.level!==3&&!["calendario","classifica","archivio"].some(s=>u.views.includes(s)))return json({error:"Non autorizzato"},403);
await db.prepare("CREATE TABLE IF NOT EXISTS fp_results (day INTEGER NOT NULL, match_no INTEGER NOT NULL, home TEXT NOT NULL, away TEXT NOT NULL, hg INTEGER NOT NULL, ag INTEGER NOT NULL, hf REAL NOT NULL, af REAL NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0, updated INTEGER, actor TEXT, PRIMARY KEY(day,match_no))").run();
const seed=[["Marco","Tomaso",4,3,87,83.5],["Fabrizio","Alfonso",5,0,94.5,65],["Paolo","Michele",4,2,89.5,76],["Daniele","Cepe",1,3,70,78.5]];
await db.batch(seed.map((r,i)=>db.prepare("INSERT OR IGNORE INTO fp_results(day,match_no,home,away,hg,ag,hf,af) VALUES (1,?,?,?,?,?,?,?)").bind(i,...r)));
if(req.method==="POST"){
if(u.level!==3||req.headers.get("Origin")!==new URL(req.url).origin)return json({error:"Non autorizzato"},403);
let b;try{b=await req.json()}catch{return json({error:"Dati non validi"},400)}
if(b.day!==1||!(b.match===null||Number.isInteger(b.match)&&b.match>=0&&b.match<4)||typeof b.confirmed!=="boolean"||(b.match===null&&!b.confirmed))return json({error:"Operazione non valida"},400);
const now=Date.now(),args=[+b.confirmed,now,u.username,b.day],sql="UPDATE fp_results SET confirmed=?,updated=?,actor=? WHERE day=?"+(b.match===null?"":" AND match_no=?");
if(b.match!==null)args.push(b.match);
await db.batch([db.prepare(sql).bind(...args),db.prepare("INSERT INTO fp_audit(actor,action,detail,created) VALUES (?,?,?,?)").bind(u.username,b.confirmed?"result_confirm":"result_reopen",JSON.stringify(b),now)]);
}else if(req.method!=="GET")return json({error:"Metodo non consentito"},405);
const rows=await db.prepare("SELECT * FROM fp_results ORDER BY day,match_no").all();return json({rows:rows.results});
}

export async function auth(req,env,path){
const db=env.DB;try{await schema(db);await permissionSchema(db);
if(path==='/api/auth/results')return await resultsApi(req,db);
if(path.startsWith('/api/auth/formation'))return await formationApi(req,db,path);
if(path==='/api/auth/rosters'||path==='/api/auth/rosters/import'||path==='/api/auth/stats/import')return await rosterApi(req,db,path);
if(['/api/auth/permissions','/api/auth/visibility','/api/auth/individual-visibility','/api/auth/account'].includes(path))return await manage(req,db,path);
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
