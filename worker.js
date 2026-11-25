export default {async fetch(request,env){
 const path=new URL(request.url).pathname;
 if(path==="/api/collaudo" && request.method==="POST"){
 try{
 if(new URL(request.url).origin!==request.headers.get("Origin"))return new Response("Origine non valida",{status:403});
 const data=await request.json();
 const b64=data.pdf;
 if(typeof b64!=="string"||b64.length>16000)return new Response("File non valido",{status:400});
 const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
 if(new TextDecoder().decode(bytes.slice(0,5))!=="%PDF-")return new Response("Non PDF",{status:400});
 const id=crypto.randomUUID();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS test_files (id TEXT PRIMARY KEY, body BLOB NOT NULL)").run();
 try{
 await env.DB.prepare("INSERT INTO test_files VALUES (?,?)").bind(id,bytes.buffer).run();
 const row=await env.DB.prepare("SELECT body FROM test_files WHERE id=?").bind(id).first();
 const restored=new Uint8Array(row.body);
 const upload=restored.length===bytes.length&&restored.every((v,i)=>v===bytes[i]);
 const password=crypto.randomUUID();
 const salt=crypto.getRandomValues(new Uint8Array(16));
 const derive=async p=>{const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(p),"PBKDF2",false,["deriveBits"]);return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256));};
 const hash=await derive(password),good=await derive(password),bad=await derive("incorrect");
 const authentication=hash.every((v,i)=>v===good[i])&&!hash.every((v,i)=>v===bad[i]);
 return Response.json({upload,authentication,bytes:bytes.length},{headers:{"Cache-Control":"no-store"}});
 }finally{await env.DB.prepare("DELETE FROM test_files WHERE id=?").bind(id).run();}
 }catch{return Response.json({error:"Collaudo non riuscito"},{status:500});}
 }

 if(path==="/api/test" && request.method==="GET"){
 try {
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS technical_test (id INTEGER PRIMARY KEY, value TEXT NOT NULL)").run();
 await env.DB.prepare("INSERT OR IGNORE INTO technical_test VALUES (1, 'test')").run();
 await env.DB.prepare("UPDATE technical_test SET value = 'verified' WHERE id=1").run();
 const row=await env.DB.prepare("SELECT value FROM technical_test WHERE id=1").first();
 return Response.json({database:row?.value==="verified",pdf:"/api/test.pdf"},{headers:{"Cache-Control":"no-store"}});
 }catch{return Response.json({database:false},{status:503});}
 }
 if(path==="/api/test.pdf" && request.method==="GET"){
 const stream="BT /F1 18 Tf 50 750 Td (FantaPapa - Test PDF) Tj ET";
 const objs=["<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>","<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>","<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>","<< /Length "+stream.length+" >>\nstream\n"+stream+"\nendstream"];
 let pdf="%PDF-1.4\n";const offsets=[0];for(const [i,o] of objs.entries()){offsets.push(pdf.length);pdf+=(i+1)+" 0 obj\n"+o+"\nendobj\n";}const start=pdf.length;pdf+="xref\n0 6\n0000000000 65535 f \n"+offsets.slice(1).map(x=>String(x).padStart(10,"0")+" 00000 n \n").join("")+"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"+start+"\n%%EOF\n";
 return new Response(pdf,{headers:{"Content-Type":"application/pdf","Content-Disposition":"attachment; filename=fantapapa-test.pdf"}});
 }
 return env.ASSETS.fetch(request);
}};