// Uses only an explicitly started localhost scanner and synthetic fixture folder.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const port = Number(process.argv[2]);
assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535, 'Pass the dedicated local test port.');
const root = path.join(__dirname, '..', '_api-fixture-' + require('node:crypto').randomUUID());
let checks=0;
function check(x,label){assert.ok(x,label);checks++;}
function request(route, headers, body='') {
 return new Promise((resolve,reject)=>{
  const req=http.request({hostname:'127.0.0.1',port,path:route,method:body?'POST':'GET',headers:{...headers,...(body?{'Content-Length':Buffer.byteLength(body)}:{})}},res=>{
   let text='';res.setEncoding('utf8');res.on('data',chunk=>text+=chunk);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,text}));
  });req.on('error',reject);req.end(body);
 });
}
async function main(){
 fs.mkdirSync(root);fs.writeFileSync(path.join(root,'plain.js'),'const answer = 42;');
 try {
  const page=await request('/',{});
  check(page.status===200,'local UI served');
  for(const key of ['content-security-policy','x-content-type-options','x-frame-options','referrer-policy']) check(Boolean(page.headers[key]),key);
  const token=/const API_TOKEN = "([^"]+)"/.exec(page.text)?.[1];check(Boolean(token),'runtime token present (never logged)');
  const headers={'Origin':`http://127.0.0.1:${port}`,'X-Scanner-Token':token,'Content-Type':'application/json'};
  const body=JSON.stringify({rootPath:root,scanMode:'full-safety-pre-scan',ruleId:'glassworm_variation_selectors',minRun:8,filter:'*',excludeDirs:'.git',excludeFiles:'*.md',maxFileSizeMb:1});
  const normal=await request('/api/scan',headers,body);check(normal.status===200,'authenticated scan');
  const result=JSON.parse(normal.text);check(result.ok && result.reportSchemaVersion===2 && result.coverage.status==='complete','schema and completion');
  check(result.riskAssessment.level==='none_detected' && result.matchCount===0,'scoped no findings');
  const stream=await request('/api/scan-stream',headers,body);
  const events=stream.text.trim().split('\n').map(JSON.parse);const streamed=events.find(e=>e.type==='result')?.result;
  check(streamed && streamed.coverage.status===result.coverage.status && streamed.matchCount===result.matchCount,'stream and ordinary API agree');
  for(const variant of [{...headers,Origin:undefined},{...headers,Origin:'https://example.invalid'},{...headers,'X-Scanner-Token':'invalid'},{...headers,Host:'example.invalid'}]){
   const clean=Object.fromEntries(Object.entries(variant).filter(([,v])=>v!==undefined));
   check((await request('/api/scan',clean,body)).status===403,'invalid origin/token/host rejected');
  }
  fs.writeFileSync(path.join(root,'package.json'),'{broken');
  const partial=JSON.parse((await request('/api/scan',headers,body)).text);
  check(partial.coverage.status==='partial' && partial.coverage.issueTotal===1,'real API reports incomplete parse');
  check(partial.errors.every(e=>e.message==='parse_failed'),'errors use fixed codes, no file contents');
  console.log(`Local HTTP regression checks passed: ${checks}`);
 } finally {
  const absolute=path.resolve(root);const boundary=path.resolve(__dirname,'..')+path.sep+'_api-fixture-';
  assert.ok(absolute.startsWith(boundary),'cleanup boundary');
  fs.rmSync(absolute,{recursive:true});
 }
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
