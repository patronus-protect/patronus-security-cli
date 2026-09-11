'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="patronus-token"]').content;
let state, draft;
const clone = value => structuredClone(value);
const labels = {pii:'PII',dlp:'DLP',prompt_injection:'Injection',threat:'Threat'};
let messageTimer;
function message(text,error=false){clearTimeout(messageTimer);messageTimer=setTimeout(()=>$('control-message').hidden=true,10000);$('control-message').hidden=false;$('control-message').textContent=text;$('control-message').classList.toggle('error',error);}
async function api(path,body){const headers={'X-Patronus-Token':token};if(body!==undefined){headers['Content-Type']='application/json';headers['If-Match']=state?.revision||'';}const response=await fetch(path,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body)});const data=await response.json();if(!response.ok)throw new Error(data.error||'Request failed');return data;}
function on(id,event,fn){$(id).addEventListener(event,async e=>{try{await fn(e);}catch(error){message(error.message,true);}});}
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function button(text,action){const b=node('button',text,'button secondary');b.type='button';b.addEventListener('click',async()=>{try{await action();}catch(error){message(error.message,true);}});return b;}
function scope(){return `${$('policy-host').value}.${$('policy-surface').value}`;}
function dirty(){return JSON.stringify(draft)!==JSON.stringify(state.profiles);}
function updateDraft(){$('draft-status').textContent=dirty()?'Unsaved changes':'No unsaved changes';renderRules();}
function renderRules(){
 const list=$('policy-list');list.replaceChildren();const search=$('policy-search').value.toLowerCase(),filter=$('policy-filter').value;
 const rules=state.rules.filter(rule=>filter===rule.category&&`${rule.id} ${rule.description}`.toLowerCase().includes(search));
 $('rule-count').textContent=`${rules.length} ${rules.length===1?'rule':'rules'}`;
 for(const rule of rules){
  const row=node('div',undefined,'policy-row'),toggle=node('input');toggle.type='checkbox';toggle.checked=draft[scope()].l1_rules[rule.id];toggle.setAttribute('aria-label',`Enable ${rule.id}`);
  toggle.addEventListener('change',()=>{draft[scope()].l1_rules[rule.id]=toggle.checked;updateDraft();});
  const summary=node('div');summary.append(node('strong',rule.id),node('small',rule.description));row.append(toggle,summary);list.append(row);
 }
}
function renderAssessments(){
 const grid=$('assessment-rules');grid.replaceChildren();
 for(const [key,title] of [['injection','Injection'],['threat','Threat']]){
  const rule=draft[scope()][key],box=node('div'),label=node('label'),enabled=node('input');enabled.type='checkbox';enabled.checked=rule.enabled;enabled.setAttribute('aria-label',`Enable ${title} assessment`);
  enabled.addEventListener('change',()=>{rule.enabled=enabled.checked;updateDraft();});label.append(enabled,document.createTextNode(` ${title}`));box.append(label);
  const levelLabel=node('label','Analysis'),level=node('select');level.setAttribute('aria-label',`${title} analysis`);
  for(const [value,text] of [['l2','L2'],['l3','L2 + L3']]){const option=node('option',text);option.value=value;level.append(option);}level.value=rule.max_level;level.addEventListener('change',()=>{rule.max_level=level.value;updateDraft();});levelLabel.append(level);box.append(levelLabel);
  grid.append(box);
 }
}
for(const id of ['policy-host','policy-surface'])on(id,'change',()=>{renderAssessments();updateDraft();});
on('policy-filter','change',renderRules);on('policy-search','input',renderRules);
on('discard-policies','click',()=>{draft=clone(state.profiles);renderAssessments();updateDraft();});
on('save-policies','click',async()=>{
 for(const [key,profile] of Object.entries(draft)){
  if(JSON.stringify(profile)===JSON.stringify(state.profiles[key]))continue;
  await api('/api/policies',{scope:key,profile});state=await api('/api/state');
 }
 draft=clone(state.profiles);renderAssessments();updateDraft();message('Policies saved. Restart active agent sessions to apply them.');
});
function renderSettings(){
 $('inference-mode').value=state.config.provider.mode;
 $('cli-update-status').textContent=state.maintenance.cargo_install?'Cargo installation detected.':state.maintenance.standalone_install?'Standalone CLI: updates use verified GitHub Release artifacts.':'Development build: install a release to enable updates.';
 for(const id of ['update-cli','uninstall-cli','uninstall-all'])$(id).disabled=!(state.maintenance.cargo_install||state.maintenance.standalone_install);
 const integrations=$('integration-settings');integrations.replaceChildren();
 for(const host of ['codex','claude','deepseek']){const row=node('div',undefined,'policy-row');row.append(node('strong',host[0].toUpperCase()+host.slice(1)));for(const action of ['enable','disable','update','uninstall'])row.append(button(action,async()=>{if(action==='uninstall'&&!confirm(`Uninstall the Patronus plugin from ${host}?`))return;const source=undefined;message(`${host}: ${action} running…`);await api('/api/integration',{host,action,source});message(`${host}: ${action} completed.`);}));integrations.append(row);}
}
on('save-settings','click',async()=>{const config=clone(state.config);config.provider.mode=$('inference-mode').value;if(config.provider.mode!=='local')config.provider.api_base_url='https://control.patronus.studio/api/v1';await api('/api/config',config);state=await api('/api/state');renderSettings();message('Inference settings saved. Restart active agent sessions to apply them.');});
window.addEventListener('beforeunload',event=>{if(state&&dirty()){event.preventDefault();event.returnValue='';}});
(async()=>{try{state=await api('/api/state');draft=clone(state.profiles);document.querySelectorAll('.server-note').forEach(el=>el.hidden=true);document.querySelectorAll('.live-controls').forEach(el=>el.hidden=false);document.querySelector('.local').textContent='Local dashboard';document.querySelector('footer').textContent=`Activity stored in ${state.data_root} · Survives CLI restarts.`;renderSettings();renderAssessments();updateDraft();await loadSetup();}catch(error){message(error.message,true);}})();

for(const [id,action,all]of [['update-cli','update',false],['uninstall-cli','uninstall',false],['uninstall-all','uninstall',true]])on(id,'click',async()=>{if(!confirm(action==='update'?'Update the CLI from its public release source?':`Uninstall ${all?'the CLI and all three plugins':'the CLI'}? Reports and settings will be preserved.`))return;message('Maintenance is running. See the CLI terminal for progress.');await api('/api/maintenance',{action,all,confirmed:true});message('Maintenance completed. Stop and restart the dashboard to use an updated CLI.');});

let usageLoading=false;
async function refreshUsage(){
 if(usageLoading)return;usageLoading=true;$('refresh-usage').disabled=true;
 try{
  const result=await api('/api/usage'),grid=$('usage-values');grid.replaceChildren();
  $('usage-panel').hidden=false;
  if(result.state!=='available'){$('usage-status').textContent=result.state==='expired'?'Sign in again to see your usage limits.':result.message||'Sign in to see usage limits.';return;}
  const {plan,usage}=result.account;$('usage-status').textContent=`${plan[0].toUpperCase()+plan.slice(1)} plan · Shared account usage · Updated ${new Date().toLocaleTimeString()}`;
  for(const [label,used,limit,reset]of [['Today',usage.daily_requests,usage.daily_limit,usage.day_resets_at],['This month',usage.monthly_requests,usage.monthly_limit,usage.month_resets_at]]){
   const box=node('div');box.append(node('h3',label),node('p',`${used.toLocaleString()} / ${limit===null?'unlimited':limit.toLocaleString()} requests`));
   if(limit!==null)box.append(node('p',`${Math.max(0,limit-used).toLocaleString()} remaining`));
   box.append(node('p',`Resets ${new Date(reset).toLocaleString()}`));grid.append(box);
  }
  const box=node('div');box.append(node('h3','Token rate'),node('p',`${usage.tokens_per_second.toLocaleString()} tokens / second`));grid.append(box);
 }catch(error){$('usage-values').replaceChildren();$('usage-panel').hidden=false;$('usage-status').textContent='Usage unavailable. Please refresh.';}
 finally{usageLoading=false;$('refresh-usage').disabled=false;}
}
on('refresh-usage','click',refreshUsage);
refreshUsage();
setInterval(()=>{if(!document.hidden)refreshUsage();},60000);

function updateScanForm(){
 const kind=$('scan-kind').value,isText=kind==='text',isMcp=kind==='mcp';
 $('scan-text-field').hidden=!isText;$('scan-target-field').hidden=isText;$('scan-server-field').hidden=!isMcp;
 const labels={url:'Public HTTPS URL',mcp:'MCP HTTPS URL or config path',file:'Absolute file path'};
 const placeholders={url:'https://example.org',mcp:'https://example.org/mcp',file:'/absolute/path/to/file.txt'};
 if(!isText){$('scan-target-field').firstChild.textContent=labels[kind];$('scan-target').placeholder=placeholders[kind];}
}
on('scan-kind','change',updateScanForm);updateScanForm();
on('scan-form','submit',async event=>{
 event.preventDefault();const kind=$('scan-kind').value,button=$('run-scan'),result=$('scan-result');button.disabled=true;$('scan-status').textContent='Scanning…';result.hidden=true;
 try{
  await api('/api/scan',{kind,target:$('scan-target').value,text:$('scan-text').value,server:$('scan-server').value});
  let job;do{await new Promise(resolve=>setTimeout(resolve,500));job=await api('/api/scan');}while(job.state==='running');
  if(job.state!=='complete')throw new Error(job.message||'Scan failed');const response=job.result;
  result.replaceChildren();const summary=node('p');summary.append(node('span',response.status,`status ${response.status.toLowerCase()}`),document.createTextNode(`${response.findings.length} findings · ${response.complete?'complete':'incomplete'} coverage`));result.append(summary);
  if(response.findings.length){const list=node('ul');for(const finding of response.findings)list.append(node('li',`${labels[finding.category]||finding.category} · ${finding.label||'signal'} · ${finding.level.toUpperCase()} · ${Math.round(finding.confidence*100)}%`));result.append(list);}
  result.hidden=false;$('scan-status').textContent='Scan complete.';
 }finally{button.disabled=false;}
});
