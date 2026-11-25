export default {async fetch(request,env){
 const path=new URL(request.url).pathname;
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