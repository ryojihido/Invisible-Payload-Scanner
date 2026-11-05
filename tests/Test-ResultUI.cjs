// Isolated DOM/network doubles for tests only. No browser, user data or services.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag = 'div') { this.tagName=tag; this.children=[]; this.events={}; this.value=''; this.style={}; this.dataset={}; this.disabled=false; this.hidden=false; this.textContent=''; this.className=''; this.classes=new Set(); this.classList={add:x=>this.classes.add(x),remove:x=>this.classes.delete(x),toggle:(x,on)=>on?this.classes.add(x):this.classes.delete(x)}; }
  appendChild(child) { this.children.push(child); return child; }
  addEventListener(name, fn) { this.events[name]=fn; }
  setAttribute(name, value) { this[name]=value; }
  click() { return this.events.click?.(); }
}
const nodes = new Map();
const document = { getElementById:id => { if(!nodes.has(id)) nodes.set(id,new Element()); return nodes.get(id); }, createElement:tag=>new Element(tag), querySelectorAll:()=>[], documentElement:new Element('html') };
const html = fs.readFileSync(path.join(__dirname,'../www/index.html'),'utf8');
const script = html.split('<script>')[1].split('</script>')[0];
const sandbox = {document,localStorage:{getItem:()=>null,setItem:()=>{}},navigator:{language:'ja'},console,Blob,URL,AbortController,TextDecoder,ReadableStream,fetch:async()=>{throw new Error('offline');}};
vm.createContext(sandbox); vm.runInContext(script,sandbox);
function run(code){return vm.runInContext(code,sandbox);}
let count=0;
function check(condition, label) { assert.ok(condition,label); count++; }
const good={ok:true,reportSchemaVersion:2,scanId:'test-id',scannedAt:'2026-10-21',matchCount:0,results:[],errors:[],summary:{},signalSummary:{},coverage:{status:'complete',enumerationComplete:true,issueTotal:0,issues:[],reasons:[],counts:{candidateFiles:1,attemptedFiles:1,completedFiles:1,failedFiles:0,notAttemptedFiles:0,observedFiles:1}},responseGuidance:{policyVersion:1,responses:[],eligibleFindingIds:[]}};
sandbox.data=good;
check(run('coverageStatus(data)')==='complete','complete scope');
check(run('getVerdict(data).level')==='neutral','no findings is neutral even when complete');
good.results=[{severity:'info',signalSeverity:'high',category:'dependency-local-test-script',pathContext:'node_modules'}];good.matchCount=1;
check(run('getVerdict(data).level')==='neutral' && run('getVerdict(data).title').includes('参考情報'),'dependency references do not warn');
good.results.push({severity:'high',category:'npm-script-danger-term',pathContext:'node_modules'});good.matchCount=2;
check(run('getVerdict(data).level')==='red','real warning alongside references remains red');
good.results=[];good.matchCount=0;
good.coverage.status='partial';good.coverage.issueTotal=1;
check(run('getVerdict(data).level')==='neutral','partial zero never green');
good.riskAssessment={level:'unknown'};
check(run('getVerdict(data).title')===run('ux("noResult")'),'all checks failed has no conclusive result');
delete good.riskAssessment;
good.coverage.status='not_assessed';good.coverage.issueTotal=0;good.coverage.counts={candidateFiles:0,attemptedFiles:0,completedFiles:0,failedFiles:0,notAttemptedFiles:0,observedFiles:0};
check(run('getVerdict(data).level')==='neutral','empty never green');
for(const version of [undefined,1,3]){good.reportSchemaVersion=version;check(run('coverageStatus(data)')==='unknown','old or unknown schema is unknown');}
good.reportSchemaVersion=2;good.coverage.status='complete';
check(run('coverageStatus(data)')==='unknown','complete with no files rejected');
good.coverage.counts={candidateFiles:1,attemptedFiles:1,completedFiles:1,failedFiles:0,notAttemptedFiles:0,observedFiles:1};
good.coverage.counts.failedFiles=-1;
check(run('coverageStatus(data)')==='unknown','negative count rejected');
good.coverage.counts.failedFiles=0;good.coverage.counts.candidateFiles=2;
check(run('coverageStatus(data)')==='unknown','inconsistent count rejected');
good.coverage.counts.candidateFiles=1;
const response={contextId:'context-1',executionContext:'install',operation:'postinstall',path:'<img src=x onerror=alert(1)>',findingIds:['f1'],strongEvidenceFindingIds:['f1'],executionState:'unanswered',stateSource:'user',executionLocation:"unknown",credentialsPresent:'unanswered'};
sandbox.response=response;
for(const state of ['unanswered','not_run','unsure']){response.executionState=state;check(!run('responseSteps(response)').includes('disconnect'),'no disconnect without reported execution');}
response.executionState='ran';
check(!run('responseSteps(response)').includes('disconnect'),'execution with unknown location no disconnect');
response.executionLocation='other_environment';
check(!run('responseSteps(response)').includes('disconnect'),'other environment no local disconnect');
response.executionLocation='this_pc';
check(run('responseSteps(response)').includes('disconnect'),'specific evidence and this-PC execution');
check(!run('responseSteps(response)').includes('keys'),'no credential action before confirmation');
response.credentialsPresent='yes';
check(run('responseSteps(response)').includes('keys'),'credential follow-up after confirmation');
response.executionContext='ci';
check(!run('responseSteps(response)').includes('disconnect'),'CI never disconnects viewing PC');
response.executionContext='package_or_code';response.strongEvidenceFindingIds=[];
check(!run('responseSteps(response)').includes('disconnect'),'package presence is not execution evidence');
good.responseGuidance.responses=[response];
run('renderGuidance(data)');
const serial = JSON.stringify(document.getElementById('guidanceCard'));
check(serial.includes('<img src=x onerror=alert(1)>'),'untrusted label retained as text');
check(!serial.includes('"innerHTML"'),'guidance never uses raw HTML');
const before = JSON.stringify(good.coverage);
for(const lang of ['ja','en']){
 run(`currentLang='${lang}'; renderCoverage(data); renderGuidance(data)`);
 check(run('responseText(data)').includes('test-id'),'text report records scan ID');
 check(run('responseText(data)').includes('f1'),'text report records evidence');
 check(run('responseText(data)').includes('postinstall') && run('responseText(data)').includes(run('ux("thisPc")')) && run('responseText(data)').includes(run('ux("credYes")')),'text report records operation and all answers');
 check(JSON.stringify(good.coverage)===before,'language changes do not change scope');
}
const keys=run('Object.keys(UX.ja)');
check(keys.every(k=>run(`typeof UX.en[${JSON.stringify(k)}]`)==='string'),'all Japanese text has English equivalent');
async function main(){
 // Simulate success followed by failure. Full production event handlers run here.
 run('lastResult=data');
 document.getElementById('rootPath').value='synthetic-folder';
 document.getElementById('scanMode').value='full-safety-pre-scan';
 await document.getElementById('scanButton').click();
 check(run('lastResult')===null,'failed rescan clears old result');
 check(document.getElementById('exportButton').disabled,'failed rescan cannot export old result');
 run("setLanguage('ja')");
 check(document.getElementById('resultSection').classes.has('hidden'),'language switch cannot resurrect stale result');
 sandbox.emptyResponse={body:new ReadableStream({start(c){c.close();}})};
 let failed=false;try{await run('readScanStream(emptyResponse)');}catch{failed=true;}
 check(failed,'EOF without result is failure');
 sandbox.fetch=async()=>{const e=new Error('cancel');e.name='AbortError';throw e;};
 run('lastResult=data');await document.getElementById('scanButton').click();
 check(run('lastResult')===null,'cancel clears previous result');
 check(document.getElementById('progressDetail').textContent.includes('最後まで'),'cancel does not display fabricated zero counts');
 console.log(`UI regression checks passed: ${count}`);
}
main().catch(e=>{console.error(e);process.exitCode=1;});
