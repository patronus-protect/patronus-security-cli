let setupState, setupHandoff, setupPoll;
async function loadSetup(){
 const data=await api('/api/onboarding');setupState=data.setup;
 $('setup-account').textContent=setupState.auth.state==='signed_in'?'Account connected. Usage is shown below.':'No active API login.';
 $('setup-logout').hidden=setupState.auth.state!=='signed_in';
 $('setup-mode').value=setupState.mode;$('setup-level').value=state.config.ark.max_level;
 $('setup-model-dir').textContent=`Model folder: ${setupState.model_dir}`;
 $('setup-models').disabled=setupState.mode==='api';
 $('setup-status').textContent=`CLI ${setupState.cli_version} · ${setupState.mode} · ${setupState.configuration_verified?'Injection test passed for saved settings':'Complete the setup steps below'}`;
 $('setup-badge').textContent=setupState.configuration_verified?'Checked':'Setup needed';
 $('setup-finish').hidden=!setupState.configuration_verified;
 if(setupState.check)showCheck(setupState.check);
 else $('setup-check-result').textContent='Run the injection check for your saved settings.';
 $('setup-restart').textContent=setupState.restart_required?'Plugin installation recorded. Start a new agent session and confirm the host reports its hooks active.':'';
 const hosts=$('setup-hosts');hosts.replaceChildren();
 if(!setupState.detected_hosts.length)hosts.append(node('p','No supported host CLI detected on PATH. Install Claude Code, Codex or DeepSeek Harness and refresh.'));
 for(const host of setupState.detected_hosts){const b=button(`Protect ${host}`,()=>startSetupJob('install',host));b.disabled=!setupState.configuration_verified;hosts.append(b);}
 showSetupJob(data.job);
}
function showCheck(b){$('setup-check-result').textContent=`${b.detected?'Injection detected':'Detection failed — review your enabled rules'} · ${b.provider}`;}
function showSetupJob(job){
 clearTimeout(setupPoll);
 $('setup-job').textContent=job.state==='running'?`${job.action} is running…`:job.state==='failed'?job.message:job.state==='completed'?`${job.action} completed.`:'';
 for(const id of ['setup-configure','setup-check'])$(id).disabled=job.state==='running';
 if(job.state==='running'){for(const b of $('setup-hosts').querySelectorAll('button'))b.disabled=true;setupPoll=setTimeout(()=>loadSetup().catch(e=>message(e.message,true)),1500);}
 if(job.state==='completed'&&job.action==='check')showCheck(job.result);
}
async function startSetupJob(action,host){const data={action};if(host)data.host=host;showSetupJob(await api('/api/onboarding',data));}
on('setup-configure','click',async()=>{await api('/api/onboarding',{action:'configure',mode:$('setup-mode').value,level:$('setup-level').value});state=await api('/api/state');draft=clone(state.profiles);renderSettings();renderAssessments();updateDraft();await loadSetup();message('Processing choices saved. Continue with models and the injection check.');});
on('setup-models','click',()=>startSetupJob('models'));
on('setup-check','click',()=>startSetupJob('check'));
on('setup-login','click',async()=>{const login=await api('/api/auth/start',{});const target=new URL(login.authorization_url);if(target.origin!=='https://control.patronus.studio')throw new Error('Unexpected login origin');setupHandoff=login.handoff_id;$('setup-login-link').href=target.href;$('setup-login-link').hidden=false;$('setup-login-form').hidden=false;message('Continue in the browser to sign in or register, then enter its one-time code here.');});
on('setup-login-form','submit',async event=>{event.preventDefault();const code=$('setup-code').value;$('setup-code').value='';try{await api('/api/auth/complete',{handoff_id:setupHandoff,code});$('setup-login-form').hidden=true;$('setup-login-link').hidden=true;await loadSetup();await refreshUsage();}catch(error){setupHandoff=undefined;throw error;}});
on('setup-logout','click',async()=>{await api('/api/auth/logout',{});await loadSetup();await refreshUsage();});

function filterActivity(){
 const query=$('activity-search').value.toLowerCase(),kind=$('activity-type').value,status=$('activity-result').value;
 for(const row of document.querySelectorAll('.activity-content tbody tr')){
  const text=row.textContent.toLowerCase(),section=row.closest('section'),heading=section.querySelector('h2')?.textContent||'';
  const source=row.dataset.remoteKind||(heading==='Protocol sessions'?'runtime':'file');
  const matches=status==='approved'?text.includes('approved')||text.includes('clean'):status==='findings'?text.includes('dangerous')||text.includes('findings'):!status||text.includes(status);
  row.hidden=!!((kind&&kind!==source)||!matches||!text.includes(query));
 }
}
for(const id of ['activity-search','activity-type','activity-result'])on(id,id==='activity-search'?'input':'change',filterActivity);
