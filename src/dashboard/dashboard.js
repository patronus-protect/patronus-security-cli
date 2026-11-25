'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="patronus-token"]').content;
let state, draft, shellDraft;
const clone = value => structuredClone(value);
const labels = {pii:'PII',dlp:'DLP',injection:'Prompt injection',jailbreak:'Jailbreak',prompt_extraction:'Prompt extraction',tool_poisoning:'Tool poisoning',exfiltration:'Exfiltration',agent_config_tampering:'Agent config tampering',memory_poisoning:'Memory poisoning',unsafe_action:'Unsafe action',resource_exhaustion:'Resource exhaustion',harmful_content:'Harmful content',toxic_language:'Toxic language'};
// Ark Core's attack classes: each has rules and a built-in L1 model.
const attackClasses = Object.keys(labels).filter(c=>c!=='pii'&&c!=='dlp');
const categoryGroups = [
 ['Personal and sensitive data', ['pii','dlp']],
 ['Attack classes', ['injection','jailbreak','prompt_extraction','tool_poisoning','exfiltration']],
 ['More attack classes (off by default)', ['agent_config_tampering','memory_poisoning','unsafe_action','resource_exhaustion','harmful_content','toxic_language']],
];
const categoryHints = {pii:'Names, contact data, IDs, payment and account numbers',dlp:'Credentials, secrets and classification markings',
 injection:'Instructions that override the user or the system',jailbreak:'Framings that switch off safety rules',prompt_extraction:'Requests for the system prompt or hidden instructions',
 tool_poisoning:'Hidden instructions in tool and MCP descriptions',exfiltration:'Data, secrets or chats sent to an outside target',
 agent_config_tampering:'Changes to agent rules, settings, hooks or MCP config',memory_poisoning:'Instructions planted in long-term memory',
 unsafe_action:'Remote execution, credential access, destructive operations',resource_exhaustion:'Requests that exhaust compute or tokens',
 harmful_content:'Requests for harmful content or actions',toxic_language:'Toxic or abusive language'};
let messageTimer;
function message(text,error=false){clearTimeout(messageTimer);messageTimer=setTimeout(()=>$('control-message').hidden=true,10000);$('control-message').hidden=false;$('control-message').textContent=text;$('control-message').classList.toggle('error',error);}
async function api(path,body){const headers={'X-Patronus-Token':token};if(body!==undefined){headers['Content-Type']='application/json';headers['If-Match']=state?.revision||'';}const response=await fetch(path,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body)});const data=await response.json();if(!response.ok)throw new Error(data.error||'Request failed');return data;}
function on(id,event,fn){$(id).addEventListener(event,async e=>{try{await fn(e);}catch(error){message(error.message,true);}});}
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function button(text,action){const b=node('button',text,'button secondary');b.type='button';b.addEventListener('click',async()=>{try{await action();}catch(error){message(error.message,true);}});return b;}
function scope(){if($('policy-host').value==='global')return 'global';return `${$('policy-host').value}.${$('policy-surface').value}`;}
function profiles(){return {...state.profiles,global:{...state.config.analysis,l1_models:{...(state.config.analysis.l1_models||{})},l1_rules:Object.fromEntries(state.rules.map(r=>[r.id,state.config.analysis.l1_rules[r.id]??r.default_enabled])),categories:[...state.config.ark.categories],wolf:state.config.ark.max_level==='l3',user_prompt_pii:state.config.analysis.user_prompt_pii}};}
function dirty(){return JSON.stringify(draft)!==JSON.stringify(profiles()) || (shellDraft&&JSON.stringify(shellDraft)!==JSON.stringify(state.config.shell));}
function updateDraft(){$('draft-status').textContent=dirty()?'Unsaved changes':'No unsaved changes';renderRules();}
function renderFilter(){
 const filter=$('policy-filter'),current=filter.value,categories=Object.keys(labels).filter(c=>state.rules.some(r=>r.category===c));
 filter.replaceChildren(...categories.map(c=>{const o=node('option',labels[c]);o.value=c;return o;}));filter.value=categories.includes(current)?current:categories[0];
}
function renderRules(){
 const list=$('policy-list');list.replaceChildren();const search=$('policy-search').value.toLowerCase(),filter=$('policy-filter').value;
 const rules=state.rules.filter(rule=>filter===rule.category&&`${rule.id} ${rule.description}`.toLowerCase().includes(search));
 $('rule-count').textContent=`${rules.length} ${rules.length===1?'rule':'rules'}`;
 for(const rule of rules){
  const row=node('div',undefined,'policy-row'),toggle=node('input');toggle.type='checkbox';toggle.checked=draft[scope()].l1_rules[rule.id];toggle.setAttribute('aria-label',`Enable ${rule.id}`);
  toggle.addEventListener('change',()=>{draft[scope()].l1_rules[rule.id]=toggle.checked;updateDraft();});
  const mode=draft[scope()][`${filter}_mode`]||state.config.analysis[`${filter}_mode`]||'strict',supported=!rule.modes||rule.modes.includes(mode);
  if(!supported){row.classList.add('rule-inactive');row.title='Requires Balanced or Recall; this rule is inactive in Strict.';}
  const summary=node('div');summary.append(node('strong',rule.id),node('small',rule.description));if(!supported)summary.append(node('small','Requires scored mode — inactive in Strict','rule-note'));row.append(toggle,summary);list.append(row);
 }
}
function toggle(label,checked,disabled,onChange){
 const wrap=node('label',undefined,'switch-label'),input=node('input');input.type='checkbox';input.checked=checked;input.disabled=disabled;input.setAttribute('aria-label',label);
 input.addEventListener('change',()=>onChange(input.checked));wrap.append(input,node('span',label.startsWith('Scan ')?'On':label.startsWith('L1 model')?'L1 model':label));return wrap;
}
function renderCategories(global){
 const table=$('global-categories');table.replaceChildren();
 const base=draft.global,editable=global;
 $('categories-note').textContent=editable
  ?"Each category runs Ark Core's rules; attack classes also run their built-in L1 model. Switch a category or its model off here."
  :'Categories and L1 models apply to every plugin. Change them under CLI defaults; this plugin adds its own rules, modes and Wolf.';
 for(const [title,members] of categoryGroups){
  table.append(node('div',title,'category-group'));
  for(const category of members){
   const enabled=base.categories.includes(category),row=node('div',undefined,'category-row');row.setAttribute('role','row');
   const name=node('div',undefined,'category-name');name.append(node('strong',labels[category]),node('small',categoryHints[category]));
   const on=toggle(`Scan ${labels[category]}`,enabled,!editable,checked=>{base.categories=base.categories.filter(c=>c!==category);if(checked)base.categories.push(category);if(category==='injection'&&!checked)base.wolf=false;updateDraft();renderAssessments();});
   row.append(name,on);
   if(attackClasses.includes(category)){
    row.append(toggle(`L1 model for ${labels[category]}`,enabled&&base.l1_models[category]!==false,!editable||!enabled,checked=>{if(checked)delete base.l1_models[category];else base.l1_models[category]=false;updateDraft();}));
   }else row.append(node('span','Rules only','category-muted'));
   table.append(row);
  }
 }
}
function renderWolf(global){
 const box=$('assessment-rules');box.replaceChildren();
 const injection=draft.global.categories.includes('injection'),profile=draft[scope()];
 const ready=state.wolf_model_ready?'Wolf Edge model is prepared.':'Wolf Edge model is not prepared yet: run Setup → Prepare missing models before saving L3.';
 if(global){
  box.append(toggle('Wolf Defender Edge (L3) for prompt injection',injection&&profile.wolf,!injection,checked=>{profile.wolf=checked;updateDraft();renderWolf(true);}));
  box.append(node('p',injection?ready:'Turn on Prompt injection to use Wolf.','setting-line'));
  return;
 }
 box.append(toggle('Wolf Defender Edge (L3) on this surface for prompt injection',injection&&profile.wolf===true,!injection,checked=>{profile.wolf=checked;updateDraft();}));
 box.append(node('p',injection?`CLI default: ${draft.global.wolf?'on':'off'}. ${ready}`:'Prompt injection is off under CLI defaults.','setting-line'));
}
function renderAssessments(){
 const global=scope()==='global',profile=draft[scope()];
 $('policy-surface').disabled=global;$('global-analysis-options').hidden=!global;
 for(const key of ['pii','dlp']){const select=$(`${key}-mode`);select.options[0].disabled=global;select.value=profile[`${key}_mode`]||(global?'strict':'');}
 $('mode-summary').textContent=`Effective modes: PII ${profile.pii_mode||state.config.analysis.pii_mode} · DLP ${profile.dlp_mode||state.config.analysis.dlp_mode}. Rules, L1 models, PII and DLP always run locally. API/Hybrid routes only send Wolf analysis.`;
 if(global)$('global-user-pii').checked=profile.user_prompt_pii;
 renderCategories(global);renderWolf(global);
}
for(const id of ['policy-host','policy-surface'])on(id,'change',()=>{renderAssessments();updateDraft();});
on('policy-filter','change',renderRules);on('policy-search','input',renderRules);
on('discard-policies','click',()=>{draft=clone(profiles());renderAssessments();updateDraft();});
for(const key of ['pii','dlp'])on(`${key}-mode`,'change',()=>{const profile=draft[scope()],value=$(`${key}-mode`).value;if(value)profile[`${key}_mode`]=value;else delete profile[`${key}_mode`];renderAssessments();updateDraft();});
on('global-user-pii','change',()=>{draft.global.user_prompt_pii=$('global-user-pii').checked;updateDraft();});
on('save-policies','click',async()=>{
 const changedProfiles=Object.entries(draft).filter(([key,profile])=>key!=='global'&&JSON.stringify(profile)!==JSON.stringify(state.profiles[key]));
 if(JSON.stringify(draft.global)!==JSON.stringify(profiles().global)){
  const config=clone(state.config),global=clone(draft.global);
  if(!global.categories.length)throw new Error('Keep at least one category on.');
  if(global.wolf&&!state.wolf_model_ready)throw new Error('Prepare the Wolf Edge model in Setup before turning on L3.');
  config.ark.categories=global.categories;config.ark.max_level=global.wolf&&global.categories.includes('injection')?'l3':'l1';delete global.categories;delete global.wolf;config.analysis=global;await api('/api/config',config);state=await api('/api/state');
 }
 for(const [key,profile] of changedProfiles){
  await api('/api/policies',{scope:key,profile});state=await api('/api/state');
 }
 draft=clone(profiles());renderAssessments();updateDraft();message('Policies saved. Restart active agent sessions to apply them.');
});
function renderSettings(){
 $('inference-mode').value=state.config.provider.mode;
 $('cli-update-status').textContent=state.maintenance.cargo_install?'Cargo installation detected.':state.maintenance.standalone_install?'Standalone CLI: updates use verified GitHub Release artifacts.':'Development build: install a release to enable updates.';
 for(const id of ['update-cli','uninstall-cli','uninstall-all'])$(id).disabled=!(state.maintenance.cargo_install||state.maintenance.standalone_install);
}
async function loadIntegrations(){
 const integrations=$('integration-settings');integrations.replaceChildren(node('p','Checking integrations…','setting-line'));
 const statuses=await api('/api/integrations');integrations.replaceChildren();
 if(!statuses.length)integrations.append(node('p','No supported integrations detected on this device.','empty-state'));
 for(const status of statuses){
  const row=node('div',undefined,'policy-row'),summary=node('div'),name=status.host==='deepseek'?'DeepSeek':status.host[0].toUpperCase()+status.host.slice(1);
  const badge=node('span',status.ready?'Active':status.state.replaceAll('_',' '),`status ${status.ready?'clean':status.state==='unavailable'||status.state==='unreachable'?'failed':'incomplete'}`);
  summary.append(node('strong',name),node('small',status.message));row.append(summary,badge);
  const actions=!status.reachable?[]:status.installed===false?['install']:status.enabled===false?['enable','update','uninstall']:status.ready?['disable','update','uninstall']:['enable','disable','update','uninstall'];
  const actionGroup=node('div',undefined,'integration-actions');
  for(const action of actions)actionGroup.append(button(action,async()=>{if(action==='uninstall'&&!confirm(`Uninstall the Patronus plugin from ${name}?`))return;message(`${name}: ${action} running…`);await api('/api/integration',{host:status.host,action});await loadIntegrations();message(`${name}: ${action} completed.`);}));
  if(actions.length)row.append(actionGroup);
  integrations.append(row);
 }
}
on('refresh-integrations','click',loadIntegrations);
on('save-settings','click',async()=>{const config=clone(state.config);config.provider.mode=$('inference-mode').value;if(config.provider.mode!=='local')config.provider.api_base_url='https://control.patronus.studio/api/v1';await api('/api/config',config);state=await api('/api/state');renderSettings();message('Inference settings saved. Restart active agent sessions to apply them.');});
window.addEventListener('beforeunload',event=>{if(state&&dirty()){event.preventDefault();event.returnValue='';}});
(async()=>{try{state=await api('/api/state');draft=clone(profiles());document.querySelectorAll('.server-note').forEach(el=>el.hidden=true);document.querySelectorAll('.live-controls').forEach(el=>el.hidden=false);document.querySelector('.local').textContent='Local dashboard';document.querySelector('footer').textContent=`Activity stored in ${state.data_root} · Survives CLI restarts.`;shellDraft=clone(state.config.shell);renderShell();renderSettings();renderFilter();renderAssessments();updateDraft();loadIntegrations().catch(error=>message(error.message,true));loadSetup().catch(error=>message(error.message,true));}catch(error){message(error.message,true);}})();

for(const [id,action,all]of [['update-cli','update',false],['uninstall-cli','uninstall',false],['uninstall-all','uninstall',true]])on(id,'click',async()=>{if(!confirm(action==='update'?'Update the CLI from its public release source?':`Uninstall ${all?'the CLI and all three plugins':'the CLI'}? Reports and settings will be preserved.`))return;message('Maintenance is running. See the CLI terminal for progress.');await api('/api/maintenance',{action,all,confirmed:true});message('Maintenance completed. Stop and restart the dashboard to use an updated CLI.');});

let usageLoading=false;
async function refreshUsage(){
 if(usageLoading)return;usageLoading=true;$('refresh-usage').disabled=true;
 try{
  const result=await api('/api/usage'),grid=$('usage-values');grid.replaceChildren();$('upgrade-cta').hidden=true;
  $('usage-panel').hidden=false;
  if(result.state!=='available'){$('usage-status').textContent=result.state==='expired'?'Sign in again to see your usage limits.':result.message||'Sign in to see usage limits.';return;}
  const {plan,usage}=result.account;$('usage-status').textContent=`${plan[0].toUpperCase()+plan.slice(1)} plan · Shared account usage · Updated ${new Date().toLocaleTimeString()}`;
  $('upgrade-cta').hidden=plan!=='free';
  for(const [label,used,limit,reset]of [['Today',usage.daily_requests,usage.daily_limit,usage.day_resets_at],['This month',usage.monthly_requests,usage.monthly_limit,usage.month_resets_at]]){
   const box=node('div');box.append(node('h3',label),node('p',`${used.toLocaleString()} / ${limit===null?'unlimited':limit.toLocaleString()} requests`));
   if(limit!==null)box.append(node('p',`${Math.max(0,limit-used).toLocaleString()} remaining`));
   box.append(node('p',`Resets ${new Date(reset).toLocaleString()}`));grid.append(box);
  }
 }catch(error){$('usage-values').replaceChildren();$('upgrade-cta').hidden=true;$('usage-panel').hidden=false;$('usage-status').textContent='Usage unavailable. Please refresh.';}
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

function shellPolicy(){return $('shell-host').value==='default'?shellDraft.default:(shellDraft.hosts[$('shell-host').value]||shellDraft.default);}
function editShell(){const host=$('shell-host').value;if(host!=='default'&&!shellDraft.hosts[host])shellDraft.hosts[host]=clone(shellDraft.default);return shellPolicy();}
function shellChanged(){$('shell-draft-status').textContent=JSON.stringify(shellDraft)===JSON.stringify(state.config.shell)?'No unsaved changes':'Unsaved shell settings';}
function renderShell(){
 const policy=shellPolicy(),host=$('shell-host').value;$('shell-ask').value=policy.ask_behavior;$('shell-inherit').disabled=host==='default'||!shellDraft.hosts[host];
 $('shell-dirs').value=policy.policy_dirs.join('\n');$('shell-allowlist').value=JSON.stringify(policy.allowlist,null,2);$('shell-rules').value=JSON.stringify(policy.rules,null,2);
 $('shell-model-status').textContent=`CLI ${state.version} · Ark ${state.ark_version} · K26 ${state.shell_model_ready?'prepared':'not prepared — run assets prepare'}${host!=='default'&&!shellDraft.hosts[host]?' · inherits global shell settings':''}`;
 const list=$('cedar-editors');list.replaceChildren();
 if(!Object.keys(policy.cedar_policies).length)list.append(node('p','No custom policies yet. Add a policy or import a Cedar file below.','empty-state'));
 for(const [name,source]of Object.entries(policy.cedar_policies)){
  const box=node('div',undefined,'cedar-editor'),bar=node('div',undefined,'control-toolbar'),label=node('label',name),area=node('textarea');area.value=source;area.spellcheck=false;area.setAttribute('aria-label',`Cedar source ${name}`);area.addEventListener('input',()=>{editShell().cedar_policies[name]=area.value;shellChanged();});
  bar.append(node('strong',name),button('Remove',()=>{delete editShell().cedar_policies[name];renderShell();}));box.append(bar,label,area);list.append(box);
 }
 shellChanged();
}
on('shell-host','change',()=>{renderShell();});
on('shell-inherit','click',()=>{delete shellDraft.hosts[$('shell-host').value];renderShell();});
on('shell-ask','change',()=>{editShell().ask_behavior=$('shell-ask').value;shellChanged();});
for(const [id,key,json]of [['shell-dirs','policy_dirs',false],['shell-allowlist','allowlist',true],['shell-rules','rules',true]])on(id,'change',()=>{editShell()[key]=json?JSON.parse($(id).value):$(id).value.split('\n').map(x=>x.trim()).filter(Boolean);shellChanged();});
const cedarExample='@id("user.no_kubectl_delete")\n@decision("block")\n@title("No kubectl deletes")\nforbid (principal, action == Action::"segment", resource)\nwhen { context.program == "kubectl" && context.verb == "DELETE" };';
on('add-cedar','click',()=>{const policy=editShell();let index=1;while(Object.hasOwn(policy.cedar_policies,`custom-${index}.cedar`))index++;policy.cedar_policies[`custom-${index}.cedar`]=cedarExample.replace('user.no_kubectl_delete',`user.custom_${index}`);renderShell();});
on('cedar-file','change',async()=>{const file=$('cedar-file').files[0];if(!file)return;if(file.size>65536)throw Error('Cedar sources must be at most 64 KiB.');const policy=editShell();if(Object.hasOwn(policy.cedar_policies,file.name))throw Error('A policy with this name already exists.');policy.cedar_policies[file.name]=await file.text();$('cedar-file').value='';renderShell();});
on('discard-shell','click',()=>{shellDraft=clone(state.config.shell);renderShell();});
on('save-shell','click',async()=>{const config=clone(state.config);config.shell=clone(shellDraft);await api('/api/config',config);state=await api('/api/state');shellDraft=clone(state.config.shell);renderShell();message('Cedar validated and shell settings saved. Restart active agent sessions to apply them.');});
on('shell-test-form','submit',async event=>{event.preventDefault();$('shell-test-submit').disabled=true;try{const result=await api('/api/shell-test',{host:$('shell-host').value,command:$('shell-test-command').value});$('shell-test-result').textContent=JSON.stringify(result,null,2);$('shell-test-result').hidden=false;}finally{$('shell-test-submit').disabled=false;}});
